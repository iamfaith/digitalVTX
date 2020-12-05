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
#include "wifibroadcast.hpp"
#include <stdexcept>
#include "Encryption.hpp"
#include "FEC.hpp"
#include "Helper.hpp"

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
    antennaItem()=default;

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

    int32_t count_all=0;
    int32_t rssi_sum=0;
    int8_t rssi_min=0;
    int8_t rssi_max=0;
};

typedef std::unordered_map<uint64_t, antennaItem> antenna_stat_t;

class Aggregator : public BaseAggregator, public FECDecoder {
public:
    Aggregator(const std::string &client_addr, int client_port, int k, int n, const std::string &keypair);

    ~Aggregator();

    void
    process_packet(const uint8_t *buf, size_t size, uint8_t wlan_idx, const uint8_t *antenna, const int8_t *rssi,
                   sockaddr_in *sockaddr) override;

    void dump_stats(FILE *fp) override;

private:
    void sendPacketViaUDP(const uint8_t *packet,std::size_t packetSize) const{
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
    const std::chrono::steady_clock::time_point INIT_TIME=std::chrono::steady_clock::now();
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
