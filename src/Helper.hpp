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
#include <stdarg.h>

// For all the stuff that was once in wifibroadcast.hpp

namespace StringFormat{
    static std::string convert(const char *format, ...){
        va_list args;
        va_start(args, format);
        size_t size = vsnprintf(nullptr, 0, format, args) + 1; // Extra space for '\0'
        va_end(args);
        std::unique_ptr<char[]> buf(new char[size]);
        va_start(args, format);
        vsnprintf(buf.get(), size, format, args);
        va_end(args);
        return std::string(buf.get(), buf.get() + size - 1); // We don't want the '\0' inside
    }
}

namespace SocketHelper{
    // originally in wifibroadcast.cpp/ h
    // I thought it might be a good idea to have all these helpers inside their own namespace
    static int open_udp_socket(const std::string &client_addr, int client_port) {
        struct sockaddr_in saddr;
        int fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (fd < 0) throw std::runtime_error(StringFormat::convert("Error opening socket: %s", strerror(errno)));

        bzero((char *) &saddr, sizeof(saddr));
        saddr.sin_family = AF_INET;
        saddr.sin_addr.s_addr = inet_addr(client_addr.c_str());
        saddr.sin_port = htons((unsigned short) client_port);

        if (connect(fd, (struct sockaddr *) &saddr, sizeof(saddr)) < 0) {
            throw std::runtime_error(StringFormat::convert("Connect error: %s", strerror(errno)));
        }
        return fd;
    }
    static int open_udp_socket_for_tx(const std::string &client_addr, int client_port) {
        struct sockaddr_in saddr;
        int fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (fd < 0) throw std::runtime_error(StringFormat::convert("Error opening socket: %s", strerror(errno)));

        bzero((char *) &saddr, sizeof(saddr));
        saddr.sin_family = AF_INET;
        saddr.sin_addr.s_addr = inet_addr(client_addr.c_str());
        saddr.sin_port = htons((unsigned short) client_port);

        if (connect(fd, (struct sockaddr *) &saddr, sizeof(saddr)) < 0) {
            throw std::runtime_error(StringFormat::convert("Connect error: %s", strerror(errno)));
        }
        return fd;
    }
    static int open_udp_socket_for_rx(int port){
        struct sockaddr_in saddr;
        int fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (fd < 0) throw std::runtime_error(StringFormat::convert("Error opening socket: %s", strerror(errno)));

        int optval = 1;
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const void *)&optval , sizeof(int));

        bzero((char *) &saddr, sizeof(saddr));
        saddr.sin_family = AF_INET;
        saddr.sin_addr.s_addr = htonl(INADDR_ANY);
        saddr.sin_port = htons((unsigned short)port);

        if (bind(fd, (struct sockaddr *) &saddr, sizeof(saddr)) < 0)
        {
            throw std::runtime_error(StringFormat::convert("Bind error: %s", strerror(errno)));
        }
        return fd;
    }
    // That's what I (Consti10) use
    static int openUdpSocketForRx(const int port){
        int fd=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (fd < 0) throw std::runtime_error(StringFormat::convert("Error opening socket %d: %s",port, strerror(errno)));
        int enable = 1;
        if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0){
            //throw std::runtime_error(StringFormat::convert("Error setting reuse on socket %d: %s",port, strerror(errno)));
            // don't crash here
            std::cout<<"Cannot set socket reuse\n";
        }
        struct sockaddr_in saddr{};
        bzero((char *) &saddr, sizeof(saddr));
        saddr.sin_family = AF_INET;
        saddr.sin_addr.s_addr = htonl(INADDR_ANY);
        saddr.sin_port = htons((unsigned short)port);
        if (bind(fd, (struct sockaddr *) &saddr, sizeof(saddr)) < 0){
            throw std::runtime_error(StringFormat::convert("Bind error on socket %d: %s",port, strerror(errno)));
        }
        return fd;
    }
}

namespace GenericHelper{
    static void fillBufferWithRandomData(std::vector<uint8_t>& data){
        const std::size_t size=data.size();
        for(std::size_t i=0;i<size;i++){
            data[i] = rand() % 255;
        }
    }
    // Create a buffer filled with random data of size sizeByes
    std::vector<uint8_t> createRandomDataBuffer(const ssize_t sizeBytes){
        std::vector<uint8_t> buf(sizeBytes);
        fillBufferWithRandomData(buf);
        return buf;
    }
    bool compareVectors(const std::vector<uint8_t>& sb,const std::vector<uint8_t>& rb){
        if(sb.size()!=rb.size()){
            return false;
        }
        const int result=memcmp (sb.data(),rb.data(),sb.size());
        return result==0;
    }
    /*constexpr std::chrono::nanoseconds timespecToDuration(timespec ts){
        auto std::chrono::duration = std::chrono::seconds{ts.tv_sec}
                        + std::chrono::nanoseconds{ts.tv_nsec};

        return std::chrono::duration_cast<std::chrono::nanoseconds>(duration);
    }*/
    using namespace std::chrono;
    constexpr nanoseconds timevalToDuration(timeval tv){
        auto duration = seconds{tv.tv_sec}
                        + microseconds {tv.tv_usec};
        return duration_cast<nanoseconds>(duration);
    }
    constexpr time_point<system_clock, nanoseconds>
    timevalToTimePoint(timeval tv){
        return time_point<system_clock, nanoseconds>{
                duration_cast<system_clock::duration>(timevalToDuration(tv))};
    }
    constexpr time_point<steady_clock, nanoseconds>
    timevalToTimePoint2(timeval tv){
        return time_point<steady_clock, nanoseconds>{
                duration_cast<steady_clock::duration>(timevalToDuration(tv))};
    }
}


#endif //WIFIBROADCAST_SOCKETHELPER_H
