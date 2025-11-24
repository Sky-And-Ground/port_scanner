/**
 * @author yuan
 * @brief  a port scanner, written in C++11, supports windows and linux platform.
 */
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <poll.h>
#endif

#include <iostream>
#include <system_error>
#include <string>
#include <bitset>
#include <thread>
#include <condition_variable>
#include <queue>
#include <functional>
#include <utility>
#include <vector>
#include <chrono>
#include <cctype>

// on windows platform, we have to do this first before we use socket.
#ifdef _WIN32
class WSALoader {
    WSALoader() {
        WSADATA wsd;
        DWORD err = WSAStartup(MAKEWORD(2, 2), &wsd);

        if (err != 0) {
            std::error_code ec(err, std::system_category());
            throw std::system_error(ec, "WSAStartup failed");
        }
    }
public:
    ~WSALoader() {
        WSACleanup();
    }

    static WSALoader& initialize() {
        static WSALoader loader;
        return loader;
    }
};
#endif

// raii wrapper for socket.
class Socket {
#ifdef _WIN32
    SOCKET sock = INVALID_SOCKET;
#else
    int sock = -1;
#endif
public:
    Socket() {}

    ~Socket() {
    #ifdef _WIN32
        if (sock != INVALID_SOCKET) {
            closesocket(sock);
        }
    #else
        if (sock >= 0) {
            close(sock);
        }
    #endif
    }

    bool open_tcp_mode() {
        sock = ::socket(AF_INET, SOCK_STREAM, 0);

    #ifdef _WIN32
        if (sock == INVALID_SOCKET) {
            return false;
        }
    #else
        if (sock < 0) {
            return false;
        }
    #endif

        return true;
    }

    bool open_udp_mode() {
        sock = ::socket(AF_INET, SOCK_DGRAM, 0);

    #ifdef _WIN32
        if (sock == INVALID_SOCKET) {
            return false;
        }
    #else
        if (sock < 0) {
            return false;
        }
    #endif

        return true;
    }

    #ifdef _WIN32
    bool connect(const std::string& ip, int port, int timeout_millisec) {
        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        
        if (inet_pton(AF_INET, ip.c_str(), &addr.sin_addr) <= 0) {
            return false;
        }

        u_long mode = 1;
        ioctlsocket(sock, FIONBIO, &mode);

        int result = ::connect(sock, (sockaddr*)&addr, sizeof(addr));
        if (result == SOCKET_ERROR) {
            if (WSAGetLastError() != WSAEWOULDBLOCK) {
                return false;
            }
        }

        fd_set writefds, exceptfds;
        FD_ZERO(&writefds);
        FD_ZERO(&exceptfds);
        FD_SET(sock, &writefds);
        FD_SET(sock, &exceptfds);

        timeval timeout;
        timeout.tv_sec = timeout_millisec / 1000;
        timeout.tv_usec = (timeout_millisec % 1000) * 1000;

        result = select(0, nullptr, &writefds, &exceptfds, &timeout);
        if (result <= 0) {
            return false;
        }

        if (FD_ISSET(sock, &exceptfds)) {
            return false;
        }

        int error = 0;
        int error_len = sizeof(error);
        if (getsockopt(sock, SOL_SOCKET, SO_ERROR, (char*)&error, &error_len) == 0) {
            return error == 0;
        }

        return false;
    }
    #else
    bool connect(const std::string& ip, int port, int timeout_millisec) {
        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        
        if (inet_pton(AF_INET, ip.c_str(), &addr.sin_addr) <= 0) {
            return false;
        }

        int flags = fcntl(sock, F_GETFL, 0);
        if (flags == -1) {
            return false;
        }

        if (fcntl(sock, F_SETFL, flags | O_NONBLOCK) == -1) {
            return false;
        }

        int result = ::connect(sock, (sockaddr*)&addr, sizeof(addr));
        if (result == 0) {
            fcntl(sock, F_SETFL, flags);
            return true;
        }

        if (errno != EINPROGRESS) {
            return false;
        }

        struct pollfd pfd;
        pfd.fd = sock;
        pfd.events = POLLOUT;
        pfd.revents = 0;

        int poll_result = poll(&pfd, 1, timeout_millisec);
        if (poll_result <= 0) {
            return false;
        }

        int error = 0;
        socklen_t error_len = sizeof(error);
        if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &error, &error_len) == -1) {
            return false;
        }

        fcntl(sock, F_SETFL, flags);
        return error == 0;
    }
    #endif
};

// thread pool.
using Task = std::function<void()>;

class TaskQueue {
    std::queue<Task> tasks;
    std::mutex mut;
    std::condition_variable cv;
    bool running = true;
public:
    void push(Task task) {
        std::lock_guard<std::mutex> guard{ mut };
        tasks.emplace(std::move(task));

        cv.notify_one();
    }

    bool pop(Task& task) {
        std::unique_lock<std::mutex> ulock{ mut };

        while (tasks.empty() && running) {
            cv.wait(ulock);
        }

        if (tasks.empty() && !running) {
            return false;
        }

        task = std::move(tasks.front());
        tasks.pop();
        return true;
    }

    void shutdown() {
        std::lock_guard<std::mutex> guard{ mut };
        running = false;
        cv.notify_all();
    }
};

class ThreadPool {
    std::vector<std::thread> workers;
    TaskQueue queue;
public:
    ThreadPool(int size) {
        workers.resize(size);

        for (int i = 0 ; i < size; ++i) {
            workers[i] = std::thread {
                [this](){
                    Task task;
                    while (queue.pop(task)) {
                        task();
                    }
                }
            };
        }
    }

    ~ThreadPool() {
        shutdown();
    }

    void submit(Task task) {
        queue.push(task);
    }

    void shutdown() {
        queue.shutdown();

        for (std::thread& t : workers) {
            if (t.joinable()) {
                t.join();
            }
        }
    }
};

class PortScan {
    using PortsTable = std::bitset<65536>;

    bool port_scan(const std::string& ip, int port, int timeout_millisec) {
        Socket sock;
        return sock.open_tcp_mode() && sock.connect(ip, port, timeout_millisec);
    }

    PortsTable ports_scan(const std::string& ip, int port_start, int port_end, int threadPoolSize, int timeout_millisec) {
        ThreadPool threadPool{ threadPoolSize };
        PortsTable table;

        for (int i = port_start; i <= port_end; ++i) {
            threadPool.submit([this, &table, &ip, i, timeout_millisec]() {
                table.set(i, port_scan(ip, i, timeout_millisec));
            });
        }

        return table;
    }
public:
    void scan(const std::string& ip, int port_start, int port_end, int thread_pool_size, int timeout_millisec) {
    #ifdef _WIN32
        WSALoader::initialize();
    #endif
        std::cout << "\nscanning all tcp ports...\n";

        auto start = std::chrono::steady_clock::now();
        auto ports_table = ports_scan(ip, port_start, port_end, thread_pool_size, timeout_millisec);
        auto end = std::chrono::steady_clock::now();

        std::cout << "scan takes " << std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count() << " ms\n";
        std::cout << "opened ports:\n";

        for (size_t i = 0; i < ports_table.size(); ++i) {
            if (ports_table.test(i)) {
                std::cout << i << " ";
            }
        }

        std::cout << "\n";
    }
};

int parse_port(const std::string& str) noexcept {
    int port = 0;

    for (char c : str) {
        if (isdigit(c)) {
            port = 10 * port + (c - '0');
        }
        else {
            return -1;
        }
    }

    if (port > 65535) {
        return -1;
    }

    return port;
}

// only for positive integers.
int str_to_int(const std::string& str) noexcept {
    int number = 0;

    for (char c : str) {
        if (isdigit(c)) {
            number = 10 * number + (c - '0');
        }
        else {
            return -1;
        }
    }

    return number;
}

// windows and linux compile commands:
// g++ port_scanner.cpp -std=c++11 -l ws2_32 -O2 -o port_scanner
// g++ port_scanner.cpp -std=c++11 -l pthread -O2 -o port_scanner
int main(int argc, char* argv[]) {
    std::string tmp;

    // get ip.
    std::string ip;
    std::cout << "ip: ";
    std::getline(std::cin, ip);

    // start port.
    std::cout << "start port: ";
    std::getline(std::cin, tmp);
    int port_start = parse_port(tmp);
    if (port_start < 0) {
        std::cerr << "invalid start port\n";
        return 1;
    }

    // end port.
    std::cout << "end port: ";
    std::getline(std::cin, tmp);
    int port_end = parse_port(tmp);
    if (port_end < 0) {
        std::cerr << "invalid end port\n";
        return 1;
    }

    // thread pool size.
    std::cout << "thread pool size: ";
    std::getline(std::cin, tmp);
    int thread_pool_size = str_to_int(tmp);
    if (thread_pool_size < 0) {
        std::cerr << "invalid thread pool size\n";
        return 1;
    }

    // timeout, milliseconds.
    std::cout << "timeout(ms): ";
    std::getline(std::cin, tmp);
    int timeout_millisec = str_to_int(tmp);
    if (timeout_millisec < 0) {
        std::cerr << "invalid timeout\n";
        return 1;
    }

    port_start = (port_start < port_end ? port_start : port_end);
    port_end = (port_start > port_end ? port_start : port_end);

    PortScan scanner;
    scanner.scan(ip, port_start, port_end, thread_pool_size, timeout_millisec);
    return 0;
}

