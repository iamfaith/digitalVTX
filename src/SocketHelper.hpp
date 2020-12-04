//
// Created by consti10 on 05.12.20.
//

#ifndef WIFIBROADCAST_SOCKETHELPER_H
#define WIFIBROADCAST_SOCKETHELPER_H
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <resolv.h>
#include <string.h>
#include <utime.h>
#include <unistd.h>
#include <getopt.h>
#include <pcap.h>
#include <endian.h>
#include <fcntl.h>
#include <time.h>
#include <sys/mman.h>
#include <sodium.h>
#include <endian.h>
#include <string>
#include <vector>
#include <chrono>

namespace SocketHelper{
    // originally in wifibroadcast.cpp/ h
    // I thought it might be a good idea to have all these helpers inside their own namespace
    static int open_udp_socket(const std::string &client_addr, int client_port) {
        struct sockaddr_in saddr;
        int fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (fd < 0) throw std::runtime_error(string_format("Error opening socket: %s", strerror(errno)));

        bzero((char *) &saddr, sizeof(saddr));
        saddr.sin_family = AF_INET;
        saddr.sin_addr.s_addr = inet_addr(client_addr.c_str());
        saddr.sin_port = htons((unsigned short) client_port);

        if (connect(fd, (struct sockaddr *) &saddr, sizeof(saddr)) < 0) {
            throw std::runtime_error(string_format("Connect error: %s", strerror(errno)));
        }
        return fd;
    }
    static int open_udp_socket_for_tx(const std::string &client_addr, int client_port) {
        struct sockaddr_in saddr;
        int fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (fd < 0) throw std::runtime_error(string_format("Error opening socket: %s", strerror(errno)));

        bzero((char *) &saddr, sizeof(saddr));
        saddr.sin_family = AF_INET;
        saddr.sin_addr.s_addr = inet_addr(client_addr.c_str());
        saddr.sin_port = htons((unsigned short) client_port);

        if (connect(fd, (struct sockaddr *) &saddr, sizeof(saddr)) < 0) {
            throw std::runtime_error(string_format("Connect error: %s", strerror(errno)));
        }
        return fd;
    }
    static int open_udp_socket_for_rx(int port){
        struct sockaddr_in saddr;
        int fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (fd < 0) throw std::runtime_error(string_format("Error opening socket: %s", strerror(errno)));

        int optval = 1;
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const void *)&optval , sizeof(int));

        bzero((char *) &saddr, sizeof(saddr));
        saddr.sin_family = AF_INET;
        saddr.sin_addr.s_addr = htonl(INADDR_ANY);
        saddr.sin_port = htons((unsigned short)port);

        if (bind(fd, (struct sockaddr *) &saddr, sizeof(saddr)) < 0)
        {
            throw std::runtime_error(string_format("Bind error: %s", strerror(errno)));
        }
        return fd;
    }
}

#endif //WIFIBROADCAST_SOCKETHELPER_H
