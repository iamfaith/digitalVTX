// -*- C++ -*-
//
#include <stdlib.h>
#include <stdarg.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string>
#include <memory>
#include <stdexcept>

#include "wifibroadcast.hpp"

std::string string_format(const char *format, ...)
{
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

uint64_t get_time_ms() // in milliseconds
{
    struct timespec ts;
    int rc = clock_gettime(CLOCK_MONOTONIC, &ts);
    if (rc < 0) throw std::runtime_error(string_format("Error getting time: %s", strerror(errno)));
    return ts.tv_sec * 1000LL + ts.tv_nsec / 1000000;
}

