# port_scanner
##### command line port scanner, written in C++11, supports windows and linux.
##### port_scanner.cpp should be built with non-boost asio, it is pretty fast on windows, but strangely slow on linux, so I wrote a port_scanner_linux.cpp to handle the linux platform.
##### the linux version, does not need any other 3rd parties, when you compile it, remember to add `-lpthread` option.
