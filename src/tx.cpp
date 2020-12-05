// -*- C++ -*-
//
// Copyright (C) 2017, 2018, 2019 Vasily Evseenko <svpcom@p2ptech.org>

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

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <poll.h>
#include <time.h>
#include <sys/resource.h>
#include <pcap/pcap.h>
#include <assert.h>
#include <chrono>
#include <memory>
#include <string>
#include <memory>
#include <vector>

#include "wifibroadcast.hpp"
#include "tx.hpp"

extern "C"{
#include "ExternalSources/fec.h"
}

namespace Helper {
    // constructs a pcap packet by prefixing data with radiotap and iee header
    static std::vector<uint8_t>
    createPcapPacket(const RadiotapHeader &radiotapHeader, const Ieee80211Header &ieee80211Header,
                     const uint8_t *buf, size_t size) {
        assert(size <= MAX_FORWARDER_PACKET_SIZE);
        std::vector<uint8_t> ret;
        ret.resize(radiotapHeader.getSize() + ieee80211Header.getSize() + size);
        uint8_t *p = ret.data();
        // radiotap header
        memcpy(p, radiotapHeader.getData(), radiotapHeader.getSize());
        p += radiotapHeader.getSize();
        // ieee80211 header
        memcpy(p, ieee80211Header.getData(), ieee80211Header.getSize());
        p += ieee80211Header.getSize();
        // data
        memcpy(p, buf, size);
        return ret;
    }
    // throw runtime exception if injecting pcap packet goes wrong (should never happen)
    static void injectPacket(pcap_t *pcap, const std::vector<uint8_t> &packetData) {
        if (pcap_inject(pcap, packetData.data(), packetData.size()) != (int)packetData.size()) {
            throw std::runtime_error(StringFormat::convert("Unable to inject packet"));
        }
    }
    // copy paste from svpcom
    static pcap_t *openTxWithPcap(const std::string &wlan) {
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_t *p = pcap_create(wlan.c_str(), errbuf);
        if (p == nullptr) {
            throw std::runtime_error(StringFormat::convert("Unable to open interface %s in pcap: %s", wlan.c_str(), errbuf));
        }
        if (pcap_set_snaplen(p, 4096) != 0) throw std::runtime_error("set_snaplen failed");
        if (pcap_set_promisc(p, 1) != 0) throw std::runtime_error("set_promisc failed");
        //if (pcap_set_rfmon(p, 1) !=0) throw runtime_error("set_rfmon failed");
        if (pcap_set_timeout(p, -1) != 0) throw std::runtime_error("set_timeout failed");
        //if (pcap_set_buffer_size(p, 2048) !=0) throw runtime_error("set_buffer_size failed");
        if (pcap_activate(p) != 0) throw std::runtime_error(StringFormat::convert("pcap_activate failed: %s", pcap_geterr(p)));
        //if (pcap_setnonblock(p, 1, errbuf) != 0) throw runtime_error(string_format("set_nonblock failed: %s", errbuf));
        return p;
    }
    // @param tx_fd: UDP ports
    static std::vector<pollfd> udpPortsToPollFd(const std::vector<int> &tx_fd){
        std::vector<pollfd> ret;
        ret.resize(tx_fd.size());
        memset(ret.data(), '\0', ret.size()*sizeof(pollfd));
        for(std::size_t i=0;i<tx_fd.size();i++){
            int fd=tx_fd[i];
            if (fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK) < 0) {
                throw std::runtime_error(StringFormat::convert("Unable to set socket into nonblocked mode: %s", strerror(errno)));
            }
            ret[i].fd = fd;
            ret[i].events = POLLIN;
        }
        return ret;
    }
}


PcapTransmitter::PcapTransmitter(RadiotapHeader radiotapHeader, int k, int n, const std::string &keypair, uint8_t radio_port,int udp_port,
                                 const std::vector<std::string> &wlans) :
        RADIO_PORT(radio_port),
        FECEncoder(k,n),
        mEncryptor(keypair),
        mRadiotapHeader(radiotapHeader){
    mEncryptor.makeSessionKey();
    callback=std::bind(&PcapTransmitter::sendFecBlock, this, std::placeholders::_1);
    for (const std::string &wlan:wlans) {
        ppcap.push_back(Helper::openTxWithPcap(wlan));
    }
    //fd = SocketHelper::open_udp_socket_for_rx(udp_port);
    mRxSocket=SocketHelper::openUdpSocketForRx(udp_port);
    fprintf(stderr, "Listen on UDP Port %d assigned ID %d assigned WLAN %s\n", udp_port,radio_port,wlans[0].c_str());
}

PcapTransmitter::~PcapTransmitter() {
    for (auto & it : ppcap) {
        pcap_close(it);
    }
    close(mRxSocket);
}


void PcapTransmitter::inject_packet(const uint8_t *buf, size_t size) {
    std::cout << "PcapTransmitter::inject_packet\n";
    mIeee80211Header.writeParams(RADIO_PORT, ieee80211_seq);
    ieee80211_seq += 16;
    const auto packet = Helper::createPcapPacket(mRadiotapHeader, mIeee80211Header, buf, size);
    Helper::injectPacket(ppcap[current_output], packet);
}

void PcapTransmitter::sendFecBlock(const XBlock &xBlock) {
    std::cout << "PcapTransmitter::sendFecBlock"<<(int)xBlock.payloadSize<<"\n";
    const auto data= mEncryptor.makeEncryptedPacket(xBlock);
    inject_packet(data.data(), data.size());
}

void PcapTransmitter::send_session_key() {
    std::cout << "PcapTransmitter::send_session_key\n";
    inject_packet((uint8_t *) &mEncryptor.session_key_packet, sizeof(mEncryptor.session_key_packet));
}

void PcapTransmitter::send_packet(const uint8_t *buf, size_t size) {
    std::cout << "PcapTransmitter::send_packet\n";
    // this calls a callback internally
    FECEncoder::encodePacket(buf,size);
    if(FECEncoder::resetOnOverflow()){
        mEncryptor.makeSessionKey();
        send_session_key();
    }
}

void PcapTransmitter::loop() {
    uint8_t buf[MAX_PAYLOAD_SIZE];
    for(;;){
        std::chrono::steady_clock::time_point session_key_announce_ts{};
        const ssize_t message_length = recvfrom(mRxSocket, buf, MAX_PAYLOAD_SIZE, MSG_WAITALL, nullptr, nullptr);
        if(message_length<0){
            if (errno == EINTR || errno == EAGAIN) continue;
            throw std::runtime_error(StringFormat::convert("recvfrom error: %s", strerror(errno)));
        }
        auto cur_ts=std::chrono::steady_clock::now();
        if (cur_ts >= session_key_announce_ts) {
            // Announce session key
            send_session_key();
            session_key_announce_ts = cur_ts + SESSION_KEY_ANNOUNCE_DELTA;
        }
        send_packet(buf,message_length);
    }
}


int main(int argc, char *const *argv) {
    int opt;
    uint8_t k = 8, n = 12, radio_port = 1;
    int udp_port = 5600;

    int bandwidth = 20;
    int short_gi = 0;
    int stbc = 0;
    int ldpc = 0;
    int mcs_index = 1;

    std::string keypair = "drone.key";

    while ((opt = getopt(argc, argv, "K:k:n:u:r:p:B:G:S:L:M:")) != -1) {
        switch (opt) {
            case 'K':
                keypair = optarg;
                break;
            case 'k':
                k = atoi(optarg);
                break;
            case 'n':
                n = atoi(optarg);
                break;
            case 'u':
                udp_port = atoi(optarg);
                break;
            case 'p':
                radio_port = atoi(optarg);
                break;
            case 'B':
                bandwidth = atoi(optarg);
                break;
            case 'G':
                short_gi = (optarg[0] == 's' || optarg[0] == 'S') ? 1 : 0;
                break;
            case 'S':
                stbc = atoi(optarg);
                break;
            case 'L':
                ldpc = atoi(optarg);
                break;
            case 'M':
                mcs_index = atoi(optarg);
                break;
            default: /* '?' */
            show_usage:
                fprintf(stderr,
                        "Usage: %s [-K tx_key] [-k RS_K] [-n RS_N] [-u udp_port] [-p radio_port] [-B bandwidth] [-G guard_interval] [-S stbc] [-L ldpc] [-M mcs_index] interface1 [interface2] ...\n",
                        argv[0]);
                fprintf(stderr,
                        "Default: K='%s', k=%d, n=%d, udp_port=%d, radio_port=%d bandwidth=%d guard_interval=%s stbc=%d ldpc=%d mcs_index=%d\n",
                        keypair.c_str(), k, n, udp_port, radio_port, bandwidth, short_gi ? "short" : "long", stbc, ldpc,
                        mcs_index);
                fprintf(stderr, "Radio MTU: %lu\n", (unsigned long) MAX_PAYLOAD_SIZE);
                fprintf(stderr, "WFB version "
                WFB_VERSION
                "\n");
                exit(1);
        }
    }

    if (optind >= argc) {
        goto show_usage;
    }
    RadiotapHeader radiotapHeader;
    radiotapHeader.writeParams(bandwidth, short_gi, stbc, ldpc, mcs_index);
    const auto wlan=argv[optind];
    try {
        std::vector<std::string> wlans;
        for (int i = 0; optind + i < argc; i++) {
            wlans.emplace_back(argv[optind + i]);
        }
        std::shared_ptr<PcapTransmitter> t = std::make_shared<PcapTransmitter>(
                radiotapHeader, k, n, keypair, radio_port,udp_port, wlans);
        t->loop();
    } catch (std::runtime_error &e) {
        fprintf(stderr, "Error: %s\n", e.what());
        exit(1);
    }
    return 0;
}

