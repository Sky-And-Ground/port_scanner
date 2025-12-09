// @date   2025-12-08
// @author yuan
// @brief  a port scanner written in C++11, only for linux platform, based on epoll mode.
#include <iostream>
#include <system_error>
#include <string>
#include <vector>
#include <array>
#include <cerrno>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/epoll.h>
#include <unistd.h>
#include <fcntl.h>

// raii wrapper for socket.
class Socket {
    int fd;
public:
    Socket() : fd{ -1 } {}

    Socket(int domain, int type, int protocol) {
        fd = socket(domain, type, protocol);
        if (fd < 0) {
            std::error_code ec(errno, std::system_category());
            throw std::system_error{ ec, "sys call socket failed" };
        }
    }

    Socket(int _fd) : fd{ _fd } {}

    Socket(const Socket&) = delete;
    Socket& operator=(const Socket&) = delete;

    Socket(Socket&& other)
        : fd{ other.fd }
    {
        other.fd = -1;
    }

    Socket& operator=(Socket&& other) {
        if (this != &other) {
            fd = other.fd;
            other.fd = -1;
        }

        return *this;
    }

    ~Socket() {
        if (fd >= 0) {
            ::close(fd);
        }
    }

    void close() {
        if (fd >= 0) {
            ::close(fd);
            fd = -1;
        }
    }

    void set_nonblock() {
        int flag = fcntl(fd, F_GETFL, 0);
        fcntl(fd, F_SETFL, flag | O_NONBLOCK);
    }

    int handle() {
        return fd;
    }
};

// raii wrapper for epoll.
class Epoll {
    int fd;
public:
    Epoll() {
        fd = epoll_create1(0);
        if (fd < 0) {
            std::error_code ec(errno, std::system_category());
            throw std::system_error{ ec, "sys call epoll_create1 failed" };
        }
    }

    Epoll(const Epoll&) = delete;
    Epoll& operator=(const Epoll&) = delete;

    Epoll(Epoll&& other)
        : fd{ other.fd }
    {
        other.fd = -1;
    }

    Epoll& operator=(Epoll&& other) {
        if (this != &other) {
            fd = other.fd;
            other.fd = -1;
        }

        return *this;
    }

    ~Epoll() {
        if (fd >= 0) {
            close(fd);
        }
    }

    int handle() {
        return fd;
    }

    void add_fd(struct epoll_event* ev, int descriptor) {
        if (epoll_ctl(fd, EPOLL_CTL_ADD, descriptor, ev) < 0) {
            std::error_code ec(errno, std::system_category());
            throw std::system_error{ ec, "sys call epoll_ctl failed on `EPOLL_CTL_ADD`" };
        }
    }
    
    void del_fd(int descriptor) {
        if (epoll_ctl(fd, EPOLL_CTL_DEL, descriptor, nullptr) < 0) {
            std::error_code ec(errno, std::system_category());
            throw std::system_error{ ec, "sys call epoll_ctl failed on `EPOLL_CTL_DEL`" };
        }
    }
};

// connector, it will do the things.
template<int N>
class BatchConnector {
    struct ConnectRecord {
        int port;
        Socket sock;
        bool opened;
    };

    std::array<ConnectRecord, N> records;
    Epoll epoll;
    int len;

    bool is_connected(int fd) {
        int error = -1;
        socklen_t len = sizeof(error);

        int ret = getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &len);
        return ret == 0 && error == 0;
    }
public:
    BatchConnector() 
        : records{}, epoll{}, len{ 0 } 
    {}

    void submit(const std::string& ip, int port) {
        // this connector could only hold N elements.
        if (len == N) {
            return;
        }

        auto& record = records[len];

        record.opened = false;
        record.port = port;

        record.sock = Socket{ AF_INET, SOCK_STREAM, 0 };
        record.sock.set_nonblock();

        struct sockaddr_in address;
        address.sin_family = AF_INET;
        address.sin_port = htons(port);
        inet_pton(AF_INET, ip.c_str(), &address.sin_addr);

        int ret = connect(record.sock.handle(), (struct sockaddr*)&address, sizeof(address));
        if (ret < 0) {
            if (errno == EINPROGRESS) {
                struct epoll_event ev;
                ev.events = EPOLLOUT | EPOLLERR | EPOLLHUP;
                ev.data.ptr = (void*)(records.data() + len);

                epoll.add_fd(&ev, record.sock.handle());
            }
            else {
                record.sock.close();
            }
        }
        else if (ret == 0) {   // hardly to happen.
            record.opened = true;
            record.sock.close();
        }

        ++len;
    }

    void collect_opened_ports(std::vector<int>& opened_ports, int timeout_millisec) {
        std::array<struct epoll_event, N> events;

        int nfds = epoll_wait(epoll.handle(), events.data(), events.size(), timeout_millisec);
        if (nfds > 0) {
            for (int i = 0; i < nfds; ++i) {
                ConnectRecord* record = (ConnectRecord*)events[i].data.ptr;

                if (events[i].events & EPOLLOUT) {
                    if (is_connected(record->sock.handle())) {
                        record->opened = true;
                    }
                }

                if (events[i].events & (EPOLLERR | EPOLLHUP)) {
                    record->opened = false;
                }
            }

            for (int i = 0; i < len; ++i) {
                if (records[i].opened) {
                    opened_ports.emplace_back(records[i].port);
                }
            }
        }
    }
};

template<int N>
std::vector<int> port_scan(const std::string& ip, const std::vector<int>& ports, int timeout_millisec) {
    std::vector<int> opened_ports;

    int i = 0;
    int counter = 0;
    while (i < ports.size()) {
        BatchConnector<N> connector;

        while (counter < N && i + counter < ports.size()) {
            connector.submit(ip, ports[i + counter]);
            ++counter;
        }

        connector.collect_opened_ports(opened_ports, timeout_millisec);

        i += counter;
        counter = 0;
    }

    return opened_ports;
}

template<int N>
std::vector<int> port_scan_range(const std::string& ip, int port_start, int port_end, int timeout_millisec) {
    std::vector<int> ports;

    for (int port = port_start; port <= port_end; ++port) {
        ports.emplace_back(port);
    }

    return port_scan<N>(ip, ports, timeout_millisec);
}

template<int N>
std::vector<int> port_scan_commonly_used(const std::string& ip, int timeout_millisec) {
    std::vector<int> ports;
    
    ports.emplace_back(21);    // ftp.
    ports.emplace_back(22);    // ssh.
    ports.emplace_back(23);    // telnet.
    ports.emplace_back(25);    // smtp.
    ports.emplace_back(53);    // dns.
    ports.emplace_back(80);    // http.
    ports.emplace_back(110);   // pop3.
    ports.emplace_back(443);   // https.
    ports.emplace_back(1433);  // sql server.
    ports.emplace_back(3306);  // mysql.
    ports.emplace_back(5432);  // pgsql.
    ports.emplace_back(6379);  // redis.
    ports.emplace_back(8000);
    ports.emplace_back(8080);

    return port_scan<N>(ip, ports, timeout_millisec);
}

int main(int argc, char* argv[]) {
    auto opened_ports = port_scan_range<256>("192.168.52.167", 0, 65535, 5000);

    for (int port : opened_ports) {
        std::cout << port << " ";
    }

    std::cout << "\n";
    return 0;
}
