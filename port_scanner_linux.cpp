/**
 * @author yuan
 * @brief  a port scanner, written in C++11, specailly for linux/bsd platform.
 */
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <poll.h>

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
#include <cstdlib>

#include "lib_config_parser.hpp"

// raii wrapper for socket.
class Socket {
    int sock = -1;
public:
    Socket() {}

    ~Socket() {
        if (sock >= 0) {
            close(sock);
        }
    }

    bool open_tcp_mode() {
        sock = ::socket(AF_INET, SOCK_STREAM, 0);

        if (sock < 0) {
            return false;
        }

        return true;
    }

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

        for (int i = 0; i < size; ++i) {
            workers[i] = std::thread{
                [this]() {
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

class PortScanner {
    using PortsTable = std::bitset<65536>;

    bool port_scan(const std::string& ip, int port, int timeout_millisec) {
        Socket sock;
        return sock.open_tcp_mode() && sock.connect(ip, port, timeout_millisec);
    }
public:
    PortsTable scan(const std::string& ip, int port_start, int port_end, int timeout_millisec) {
        ThreadPool threadPool{ 256 };
        PortsTable table;

        for (int i = port_start; i <= port_end; ++i) {
            threadPool.submit([this, &table, &ip, i, timeout_millisec]() {
                table.set(i, port_scan(ip, i, timeout_millisec));
                });
        }

        return table;
    }
};

// some utils.
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

int parse_positive_integer(const std::string& str) noexcept {
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

// config.
enum class ConfigExtractError {
    success,

    not_found_ip,
    not_found_port_start,
    not_found_port_end,
    not_found_timeout_millisec,

    invalid_port_start,
    invalid_port_end,
    invalid_timeout_millisec
};

struct Config {
    std::string ip;
    int port_start;
    int port_end;
    int timeout_millisec;
};

const char* config_extract_strerr(ConfigExtractError err) {
    switch(err) {
        case ConfigExtractError::success:
            return "config extract success";
        case ConfigExtractError::not_found_ip:
            return "config not found: ip";
        case ConfigExtractError::not_found_port_start:
            return "config not found: port_start";
        case ConfigExtractError::not_found_port_end:
            return "config not found: port_end";
        case ConfigExtractError::not_found_timeout_millisec:
            return "config not found: timeout_millisec";
        case ConfigExtractError::invalid_port_start:
            return "config invalid: port_start";
        case ConfigExtractError::invalid_port_end:
            return "config invalid: port_end";
        case ConfigExtractError::invalid_timeout_millisec:
            return "config invalid: timeout_millisec";
        default:
            return "unknown config extract error";
    }
}

ConfigExtractError config_extract(const std::map<std::string, std::string>& configMap, Config& config) {
    const std::string config_ip = "ip";
    const std::string config_port_start = "port_start";
    const std::string config_port_end = "port_end";
    const std::string config_timeout_millisec = "timeout_millisec";

    auto ip_iter = configMap.find(config_ip);
    if (ip_iter == configMap.cend()) {
        return ConfigExtractError::not_found_ip;
    }

    auto port_start_iter = configMap.find(config_port_start);
    if (port_start_iter == configMap.cend()) {
        return ConfigExtractError::not_found_port_start;
    }

    auto port_end_iter = configMap.find(config_port_end);
    if (port_end_iter == configMap.cend()) {
        return ConfigExtractError::not_found_port_end;
    }

    auto timeout_millisec_iter = configMap.find(config_timeout_millisec);
    if (timeout_millisec_iter == configMap.cend()) {
        return ConfigExtractError::not_found_timeout_millisec;
    }

    config.ip = ip_iter->second;
    
    int port_start = parse_positive_integer(port_start_iter->second);
    if (port_start < 0) {
        return ConfigExtractError::invalid_port_start;
    }

    int port_end = parse_positive_integer(port_end_iter->second);
    if (port_end < 0) {
        return ConfigExtractError::invalid_port_end;
    }

    int timeout_millisec = parse_positive_integer(timeout_millisec_iter->second);
    if (timeout_millisec < 0) {
        return ConfigExtractError::invalid_timeout_millisec;
    }

    config.port_start = (port_start < port_end ? port_start : port_end);
    config.port_end = (port_start > port_end ? port_start : port_end);
    config.timeout_millisec = timeout_millisec;
    return ConfigExtractError::success;
}

// g++ port_scanner.cpp -std=c++11 -l pthread -O2 -s -o port_scanner
int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "usage: " << argv[0] << " <config_file>\n";
        return 1;
    }

    try {
        // get config.
        config_parser::ConfigParser parser;
        auto configMap = parser.parse(argv[1]);

        Config config;
        auto extractRet = config_extract(configMap, config);

        if (extractRet != ConfigExtractError::success) {
            std::cerr << config_extract_strerr(extractRet) << "\n";
            return 1;
        }

        // scan.
        PortScanner scanner;

        std::cout << "ip: " << config.ip << "\n";
        std::cout << "ports: " << config.port_start << " to " << config.port_end << "\n";
        std::cout << "timeout limit: " << config.timeout_millisec << "ms\n";
        std::cout << "\nscanning...\n";

        auto start = std::chrono::steady_clock::now();
        auto portsTable = scanner.scan(config.ip, config.port_start, config.port_end, config.timeout_millisec);
        auto end = std::chrono::steady_clock::now();

        // print result.
        std::cout << "scan takes " << std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count() << " ms\n";
        std::cout << "\nopened tcp ports: ";

        for (size_t i = 0; i < portsTable.size(); ++i) {
            if (portsTable.test(i)) {
                std::cout << i << " ";
            }
        }

        std::cout << "\n";
    }
    catch(const config_parser::FileNotFoundException& e) {
        std::cerr << "given config file does not exist\n";
        return 1;
    }

    return 0;
}
