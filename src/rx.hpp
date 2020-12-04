// -*- C++ -*-
//
// Copyright (C) 2017, 2018 Vasily Evseenko <svpcom@p2ptech.org>

/*
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; version 3.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License along
 *   with this program; if not, write to the Free Software Foundation, Inc.,
 *   51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <unordered_map>
#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <errno.h>
#include <string>
#include <string.h>
#include "fec.h"
#include "wifibroadcast.hpp"
#include <stdexcept>
#include "Encryption.hpp"
#include "FEC.hpp"

typedef enum {
    LOCAL,
    FORWARDER,
    AGGREGATOR
} rx_mode_t;

class BaseAggregator {
public:
    virtual void
    process_packet(const uint8_t *buf, size_t size, uint8_t wlan_idx, const uint8_t *antenna, const int8_t *rssi,
                   sockaddr_in *sockaddr) = 0;

    virtual void dump_stats(FILE *fp) = 0;

protected:
    int open_udp_socket_for_tx(const std::string &client_addr, int client_port) {
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
};


class Forwarder : public BaseAggregator {
public:
    Forwarder(const std::string &client_addr, int client_port);

    ~Forwarder();

    virtual void
    process_packet(const uint8_t *buf, size_t size, uint8_t wlan_idx, const uint8_t *antenna, const int8_t *rssi,
                   sockaddr_in *sockaddr);

    virtual void dump_stats(FILE *) {}

private:
    int sockfd;
};


class antennaItem {
public:
    antennaItem() : count_all(0), rssi_sum(0), rssi_min(0), rssi_max(0) {}

    void log_rssi(int8_t rssi) {
        if (count_all == 0) {
            rssi_min = rssi;
            rssi_max = rssi;
        } else {
            rssi_min = std::min(rssi, rssi_min);
            rssi_max = std::max(rssi, rssi_max);
        }
        rssi_sum += rssi;
        count_all += 1;
    }

    int32_t count_all;
    int32_t rssi_sum;
    int8_t rssi_min;
    int8_t rssi_max;
};

typedef std::unordered_map<uint64_t, antennaItem> antenna_stat_t;

class Aggregator : public BaseAggregator, public FECDecoder {
public:
    Aggregator(const std::string &client_addr, int client_port, int k, int n, const std::string &keypair);

    ~Aggregator();

    virtual void
    process_packet(const uint8_t *buf, size_t size, uint8_t wlan_idx, const uint8_t *antenna, const int8_t *rssi,
                   sockaddr_in *sockaddr);

    virtual void dump_stats(FILE *fp);

private:
    void send_packet(int ring_idx, int fragment_idx);

    void sendPacketViaUDP(const uint8_t *packet,std::size_t packetSize){
        send(sockfd,packet,packetSize, MSG_DONTWAIT);
    }

    void log_rssi(const sockaddr_in *sockaddr, uint8_t wlan_idx, const uint8_t *ant, const int8_t *rssi);

    int sockfd;
    Decryptor mDecryptor;
    antenna_stat_t antenna_stat;
    uint32_t count_p_all;
    uint32_t count_p_dec_err;
    uint32_t count_p_dec_ok;
    //uint32_t count_p_fec_recovered;
    //uint32_t count_p_lost;
    //uint32_t count_p_bad;
};

class Receiver {
public:
    Receiver(const char *wlan, int wlan_idx, int port, BaseAggregator *agg);

    ~Receiver();

    void loop_iter();

    int getfd() const { return fd; }

private:
    const int wlan_idx;
    BaseAggregator *agg;
    int fd;
    pcap_t *ppcap;
};
