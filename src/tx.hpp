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

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <errno.h>
#include <string>
#include <vector>
#include <string.h>
#include "fec.h"
#include "wifibroadcast.hpp"
#include <stdexcept>
#include <iostream>

#include "Encryption.hpp"
#include "FEC.hpp"

class Transmitter: public FECEncoder
{
public:
    Transmitter(RadiotapHeader radiotapHeader,int k, int m, const std::string &keypair);
    virtual ~Transmitter();
    void send_packet(const uint8_t *buf, size_t size);
    void send_session_key();
    virtual void select_output(int idx) = 0;
protected:
    // What inject_packet does is left to the implementation (e.g. PcapTransmitter)
    virtual void inject_packet(const uint8_t *buf, size_t size) = 0;
private:
    void send_block_fragment(size_t packet_size);
    void make_session_key();

    /*fec_t* fec_p;
    const int fec_k;  // RS number of primary fragments in block
    const int fec_n;  // RS total number of fragments in block
    uint64_t block_idx; //block_idx << 8 + fragment_idx = nonce (64bit)
    uint8_t fragment_idx;
    uint8_t** block;
    size_t max_packet_size;*/
    //FECEncoder mFECEncoder;
    Encryptor mEncryptor;
protected:
    Ieee80211Header mIeee80211Header;
public:
    // const since params like bandwidth never change !
    const RadiotapHeader mRadiotapHeader;
};

// Pcap Transmitter injects packets into the wifi adapter using pcap
class PcapTransmitter : public Transmitter
{
public:
    PcapTransmitter(RadiotapHeader radiotapHeader,int k, int m, const std::string &keypair, uint8_t radio_port, const std::vector<std::string> &wlans);
    virtual ~PcapTransmitter();
    virtual void select_output(int idx) { current_output = idx; }
private:
    virtual void inject_packet(const uint8_t *buf, size_t size);
    // the radio port is what is used as an index to multiplex multiple streams (telemetry,video,...)
    // into the one wfb stream
    const uint8_t radio_port;
    // TODO what the heck is this one ?
    // I think it is supposed to be the wifi interface data is sent on
    int current_output;
    uint16_t ieee80211_seq;
    std::vector<pcap_t*> ppcap;
};

// UdpTransmitter can be used to emulate a wifi bridge without using a wifi adapter
// Usefully for Testing and Debugging.
// Use the Aggregator functionality as rx when using UdpTransmitter
class UdpTransmitter : public Transmitter
{
public:
    UdpTransmitter(int k, int m, const std::string &keypair, const std::string &client_addr, int client_port) : Transmitter({},k, m, keypair)
    {
        sockfd = open_udp_socket(client_addr, client_port);
    }

    virtual ~UdpTransmitter()
    {
        close(sockfd);
    }

    virtual void select_output(int /*idx*/){}

private:
    virtual void inject_packet(const uint8_t *buf, size_t size);

    static int open_udp_socket(const std::string &client_addr, int client_port)
    {
        struct sockaddr_in saddr;
        int fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (fd < 0) throw std::runtime_error(string_format("Error opening socket: %s", strerror(errno)));

        bzero((char *) &saddr, sizeof(saddr));
        saddr.sin_family = AF_INET;
        saddr.sin_addr.s_addr = inet_addr(client_addr.c_str());
        saddr.sin_port = htons((unsigned short)client_port);

        if (connect(fd, (struct sockaddr *) &saddr, sizeof(saddr)) < 0)
        {
            throw std::runtime_error(string_format("Connect error: %s", strerror(errno)));
        }
        return fd;
    }

    int sockfd;
};
