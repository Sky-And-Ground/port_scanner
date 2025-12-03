/*
    @author yuan
    @brief  a port scanner written in C++11, with non-boost asio library.
*/
#include <iostream>
#include <string>
#include <bitset>
#include <vector>
#include <chrono>
#include <memory>
#include <cctype>

#include <asio.hpp>
#include "lib_config_parser.hpp"

// port scanner.
class PortScanner {
    using PortsTable = std::bitset<65536>;

    asio::io_context ioc;
    PortsTable table;

    void port_scan(const std::string& ip, int port, int timeout_millisec) {
        auto socket = std::make_shared<asio::ip::tcp::socket>(ioc);
        asio::ip::tcp::endpoint endpoint(asio::ip::make_address(ip), port);
        
        socket->async_connect(endpoint, 
            [this, port, socket](const std::error_code& ec) {
                if (!ec) {
                    table.set(port, true);
                }
            });
        
        auto timer = std::make_shared<asio::steady_timer>(ioc);
        timer->expires_after(std::chrono::milliseconds(timeout_millisec));
        timer->async_wait([socket, timer](const std::error_code& ec) {
            if (!ec) {
                if (socket->is_open()) {
                    socket->cancel();
                }
            }
        });
    }

    void scan_all(const std::string& ip, int port_start, int port_end, int timeout_millisec) {
        for (int i = port_start; i <= port_end; ++i) {
            if (!table.test(i)) {
                port_scan(ip, i, timeout_millisec);
            }
        }
    }
public:
    PortScanner() : ioc{}, table{} {}

    void scan(const std::string& ip, int port_start, int port_end, int timeout_millisec) {
        // scan 3 times, to increase the scan quality, especially for bad network environment.
        scan_all(ip, port_start, port_end, timeout_millisec);
        scan_all(ip, port_start, port_end, timeout_millisec);
        scan_all(ip, port_start, port_end, timeout_millisec);

        ioc.run();
    }

    const PortsTable& get_ports_table() {
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

// g++ port_scanner.cpp -I D:\\third-party\\asio-master\\asio\\include -std=c++11 -l ws2_32 -O2 -s -o port_scanner
// g++ port_scanner.cpp -I /home/3rd_party/asio-master/asio/include -std=c++11 -O2 -s -o port_scanner
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
        scanner.scan(config.ip, config.port_start, config.port_end, config.timeout_millisec);
        auto end = std::chrono::steady_clock::now();

        // print result.
        std::cout << "scan takes " << std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count() << " ms\n";
        std::cout << "\nopened tcp ports: ";

        const auto& portsTable = scanner.get_ports_table();
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
    catch(const asio::system_error& se) {
        std::cerr << "asio system error, " << se.code() << ", " << se.what() << "\n";
        return 1;
    }

    return 0;
}
