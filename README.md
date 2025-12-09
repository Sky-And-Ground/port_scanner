# port_scanner
##### command line port scanner, written in C++11, supports windows and linux.
##### `port_scanner.cpp` should be built with non-boost asio, it is pretty fast on my windows.
##### the special linux version is just for my company's machines, they just has a g++4.8.5, cannot compile asio. This special version does not need any other 3rd parties, it is base on epoll model.
