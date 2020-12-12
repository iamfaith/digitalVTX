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
#include "ExternalCSources/fec.h"
}

namespace Helper {
    // construct a pcap packet with the following data layout:
    // RadiotapHeader | Ieee80211Header | customHeader | payload
    // both customHeader and payload can have size 0, in this case there is nothing written for customHeader or payload
    static std::vector<uint8_t>
    createPcapPacket(const RadiotapHeader &radiotapHeader, const Ieee80211Header &ieee80211Header,
                      const uint8_t *customHeader, std::size_t customHeaderSize, const uint8_t *payload, std::size_t payloadSize) {
        const auto customHeaderAndPayloadSize=customHeaderSize + payloadSize;
        assert((customHeaderAndPayloadSize) <= MAX_FORWARDER_PACKET_SIZE);
        std::vector<uint8_t> ret;
        ret.resize(radiotapHeader.getSize() + ieee80211Header.getSize() + customHeaderAndPayloadSize);
        uint8_t *p = ret.data();
        // radiotap wbDataHeader
        memcpy(p, radiotapHeader.getData(), radiotapHeader.getSize());
        p += radiotapHeader.getSize();
        // ieee80211 wbDataHeader
        memcpy(p, ieee80211Header.getData(), ieee80211Header.getSize());
        p += ieee80211Header.getSize();
        if(customHeaderSize>0){
            // customHeader
            memcpy(p, customHeader, customHeaderSize);
            p+=customHeaderSize;
        }
        if(payloadSize>0){
            // payload
            memcpy(p, payload, payloadSize);
        }
        return ret;
    }
    // same as above, but only works if customHeader and payload are stored at the same memory location or
    // the implementation doesn't need a custom wbDataHeader
    static std::vector<uint8_t>
    createPcapPacket(const RadiotapHeader &radiotapHeader, const Ieee80211Header &ieee80211Header,
                     const uint8_t *buf, size_t size) {
        return createPcapPacket(radiotapHeader,ieee80211Header,buf,size, nullptr,0);
    }
    // throw runtime exception if injecting pcap packet goes wrong (should never happen)
    static void injectPacket(pcap_t *pcap, const std::vector<uint8_t> &packetData) {
        if (pcap_inject(pcap, packetData.data(), packetData.size()) != (int)packetData.size()) {
            throw std::runtime_error(StringFormat::convert("Unable to inject packet %s",pcap_geterr(pcap)));
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

PcapTransmitter::PcapTransmitter(const std::string &wlan) {
    ppcap=Helper::openTxWithPcap(wlan);
}

void PcapTransmitter::injectPacket(const RadiotapHeader &radiotapHeader, const Ieee80211Header &ieee80211Header,
                                   const uint8_t *payload, std::size_t payloadSize) {
    pcapInjectionTime.start();
    const auto packet = Helper::createPcapPacket(radiotapHeader, ieee80211Header, payload, payloadSize);
    Helper::injectPacket(ppcap, packet);
    pcapInjectionTime.stop();
#ifdef ENABLE_ADVANCED_DEBUGGING
    if(pcapInjectionTime.getMax()>std::chrono::milliseconds (1)){
        std::cerr<<"Injecting PCAP packet took really long:"<<pcapInjectionTime.getAvgReadable()<<"\n";
        pcapInjectionTime.reset();
    }
#endif
}

void PcapTransmitter::injectPacket2(const RadiotapHeader &radiotapHeader, const Ieee80211Header &ieee80211Header,
                                    const uint8_t *customHeader, std::size_t customHeaderSize, const uint8_t *payload,
                                    std::size_t payloadSize) {
    const auto packet = Helper::createPcapPacket(radiotapHeader, ieee80211Header, customHeader, customHeaderSize, payload, payloadSize);
    Helper::injectPacket(ppcap, packet);
}

PcapTransmitter::~PcapTransmitter() {
    pcap_close(ppcap);
}

RawSocketTransmitter::RawSocketTransmitter(const std::string &wlan) {
    sockFd=SocketHelper::openWifiInterfaceAsTx(wlan);
}

RawSocketTransmitter::~RawSocketTransmitter() {
    close(sockFd);
}

void RawSocketTransmitter::injectPacket(const RadiotapHeader &radiotapHeader, const Ieee80211Header &ieee80211Header,
                                        const uint8_t *payload, std::size_t payloadSize) {
    const auto packet = Helper::createPcapPacket(radiotapHeader, ieee80211Header, payload, payloadSize);
    if (write(sockFd,packet.data(),packet.size()) !=packet.size()) {
        throw std::runtime_error(StringFormat::convert("Unable to inject packet (raw sock) %s",strerror(errno)));
    }
}

WBTransmitter::WBTransmitter(RadiotapHeader radiotapHeader, int k, int n, const std::string &keypair, uint8_t radio_port, int udp_port,
                             const std::string &wlan) :
        FECEncoder(k,n),
        mPcapTransmitter(wlan),
        RADIO_PORT(radio_port),
        mEncryptor(keypair),
        mRadiotapHeader(radiotapHeader){
    mEncryptor.makeSessionKey();
    callback=std::bind(&WBTransmitter::sendFecBlock, this, std::placeholders::_1);
    mInputSocket=SocketHelper::openUdpSocketForRx(udp_port, WBTransmitter::LOG_INTERVAL);
    fprintf(stderr, "WB-TX Listen on UDP Port %d assigned ID %d assigned WLAN %s\n", udp_port,radio_port,wlan.c_str());
}

WBTransmitter::~WBTransmitter() {
    close(mInputSocket);
}


void WBTransmitter::sendPacket(const uint8_t *buf, size_t size) {
    //std::cout << "WBTransmitter::inject_packet\n";
    mIeee80211Header.writeParams(RADIO_PORT, ieee80211_seq);
    ieee80211_seq += 16;
    //mPcapTransmitter.injectPacket2(mRadiotapHeader,mIeee80211Header,customHeader,customHeaderSize,payload,payloadSize);
    mPcapTransmitter.injectPacket(mRadiotapHeader,mIeee80211Header,buf,size);
    nInjectedPackets++;
}

void WBTransmitter::sendFecBlock(const WBDataPacket &wbDataPacket) {
    //std::cout << "WBTransmitter::sendFecBlock"<<(int)wbDataPacket.payloadSize<<"\n";
    const auto data= mEncryptor.makeEncryptedPacketIncludingHeader(wbDataPacket);
    sendPacket(data.data(), data.size());
    //const auto encryptedWBDataPacket=mEncryptor.encryptWBDataPacket(wbDataPacket);
    //sendPacket((uint8_t*)&encryptedWBDataPacket.wbDataHeader,sizeof(WBDataHeader),encryptedWBDataPacket.payload,encryptedWBDataPacket.payloadSize);
#ifdef ENABLE_ADVANCED_DEBUGGING
    //LatencyTestingPacket latencyTestingPacket;
    //sendPacket((uint8_t*)&latencyTestingPacket,sizeof(latencyTestingPacket));
#endif
}

void WBTransmitter::sendSessionKey() {
    std::cout << "sendSessionKey()\n";
    sendPacket((uint8_t *) &mEncryptor.sessionKeyPacket, WBSessionKeyPacket::SIZE_BYTES);
}

void WBTransmitter::processPacket(const uint8_t *buf, size_t size) {
    //std::cout << "WBTransmitter::send_packet\n";
    // this calls a callback internally
    FECEncoder::encodePacket(buf,size);
    if(FECEncoder::resetOnOverflow()){
        // running out of sequence numbers should never happen during the lifetime of the TX instance
        mEncryptor.makeSessionKey();
        sendSessionKey();
    }
}

void WBTransmitter::loop() {
    uint8_t buf[MAX_PAYLOAD_SIZE];
    std::chrono::steady_clock::time_point session_key_announce_ts{};
    std::chrono::steady_clock::time_point log_ts{};
    for(;;){
        const ssize_t message_length = recvfrom(mInputSocket, buf, MAX_PAYLOAD_SIZE, 0, nullptr, nullptr);
        if(std::chrono::steady_clock::now()>=log_ts){
            const auto runTimeMs=std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now()-INIT_TIME).count();
            std::cout<<StringFormat::convert("%d \tTX %d:%d",runTimeMs,nPacketsFromUdpPort,nInjectedPackets)<<"\n";
            //<<" nPacketsFromUdpPort: "<<nPacketsFromUdpPort<<" nInjectedPackets: "<<nInjectedPackets<<"\n";
            log_ts= std::chrono::steady_clock::now() + WBTransmitter::LOG_INTERVAL;
        }
        if(message_length>0){
            nPacketsFromUdpPort++;
            const auto cur_ts=std::chrono::steady_clock::now();
            if (cur_ts >= session_key_announce_ts) {
                // Announce session key
                sendSessionKey();
                session_key_announce_ts = cur_ts + SESSION_KEY_ANNOUNCE_DELTA;
            }
            processPacket(buf,message_length);
        }else{
            if(errno==EAGAIN || errno==EWOULDBLOCK){
                // timeout
                continue;
            }
            if (errno == EINTR){
                std::cout<<"Got EINTR"<<"\n";
                continue;
            }
            throw std::runtime_error(StringFormat::convert("recvfrom error: %s", strerror(errno)));
        }
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

    std::cout<<"MAX_PAYLOAD_SIZE:"<<MAX_PAYLOAD_SIZE<<"\n";

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
                        "Usage: %s [-K tx_key] [-k RS_K] [-n RS_N] [-u udp_port] [-p radio_port] [-B bandwidth] [-G guard_interval] [-S stbc] [-L ldpc] [-M mcs_index] interface \n",
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
    const auto wlan=argv[optind];
    RadiotapHeader radiotapHeader;
    radiotapHeader.writeParams(bandwidth, short_gi, stbc, ldpc, mcs_index);
    try {
        std::shared_ptr<WBTransmitter> t = std::make_shared<WBTransmitter>(
                radiotapHeader, k, n, keypair, radio_port,udp_port, wlan);
        t->loop();
    } catch (std::runtime_error &e) {
        fprintf(stderr, "Error: %s\n", e.what());
        exit(1);
    }
    return 0;
}

