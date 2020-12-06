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


class antennaItem {
public:
    antennaItem()=default;

    void addRSSI(int8_t rssi) {
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


// This class processes the received wifi data
// and forwards it via UDP
// optionally this also forwards the stats via UDP
class Aggregator :  public FECDecoder {
public:
    Aggregator(const std::string &client_addr, int client_udp_port, int k, int n, const std::string &keypair);

    ~Aggregator();

    void
    process_packet(const uint8_t *payload, size_t payloadSize, uint8_t wlan_idx, const uint8_t *antenna, const int8_t *rssi) ;

    void dump_stats(FILE *fp) ;
    const int CLIENT_UDP_PORT;
private:
    void sendPacketViaUDP(const uint8_t *packet,std::size_t packetSize) const{
        send(sockfd,packet,packetSize, MSG_DONTWAIT);
    }
    int sockfd;
    Decryptor mDecryptor;
    antenna_stat_t antenna_stat;
    uint32_t count_p_all=0;
    uint32_t count_p_dec_err=0;
    uint32_t count_p_dec_ok=0;
    const std::chrono::steady_clock::time_point INIT_TIME=std::chrono::steady_clock::now();
};

// This class listens for WIFI data on the specified wlan and the assigned id
// Processing of data is done by the Aggregator
class Receiver {
public:
    Receiver(const std::string wlan, int wlan_idx, int radio_port, Aggregator *agg);

    ~Receiver();

    void loop_iter();

    int getfd() const { return fd; }
private:
    const int wlan_idx;
    Aggregator *agg;
    int fd;
    pcap_t *ppcap;
    // n of pcap packets received
    // n of pcap packets forwarded
};
