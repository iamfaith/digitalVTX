
// Copyright (C) 2017, 2018, 2019 Vasily Evseenko <svpcom@p2ptech.org>
// 2020 Constantin Geier
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

#include "tx.hpp"
#include "HelperSources/SchedulingHelper.hpp"

#include <cstdio>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <poll.h>
#include <ctime>
#include <sys/resource.h>
#include <pcap/pcap.h>
#include <cassert>
#include <chrono>
#include <memory>
#include <string>
#include <memory>
#include <vector>
#include <thread>


WBTransmitter::WBTransmitter(RadiotapHeader radiotapHeader, int k, int n, const std::string &keypair, uint8_t radio_port, int udp_port,
                             const std::string &wlan,const std::chrono::milliseconds flushInterval) :
        FECEncoder(k,n),
        mPcapTransmitter(wlan),
        RADIO_PORT(radio_port),
        mEncryptor(keypair),
        mRadiotapHeader(radiotapHeader),
        FLUSH_INTERVAL(flushInterval){
    if(FLUSH_INTERVAL>LOG_INTERVAL){
        std::cerr<<"Please use a flush interval smaller than the log interval\n";
    }
    if(FLUSH_INTERVAL==std::chrono::milliseconds(0)){
        std::cerr<<"Please do not use a flush interval of 0 (would hog the cpu)\n";
    }
    mEncryptor.makeNewSessionKey(sessionKeyPacket.sessionKeyNonce, sessionKeyPacket.sessionKeyData);
    outputDataCallback=std::bind(&WBTransmitter::sendFecBlock, this, std::placeholders::_1,std::placeholders::_2,std::placeholders::_3);
    mInputSocket=SocketHelper::openUdpSocketForRx(udp_port);
    fprintf(stderr, "WB-TX Listen on UDP Port %d assigned ID %d assigned WLAN %s FLUSH_INTERVAL(ms) %d\n", udp_port,radio_port,wlan.c_str(),(int)flushInterval.count());
    // Don't forget to write K,N into the session key packet. K,N Doesn't change on the tx
    sessionKeyPacket.FEC_N_PRIMARY_FRAGMENTS=FECEncoder::fec.N_PRIMARY_FRAGMENTS;
    sessionKeyPacket.FEC_N_SECONDARY_FRAGMENTS=FECEncoder::fec.N_SECONDARY_FRAGMENTS;
}

WBTransmitter::~WBTransmitter() {
    close(mInputSocket);
}


void WBTransmitter::sendPacket(const AbstractWBPacket& abstractWbPacket) {
    //std::cout << "WBTransmitter::sendPacket\n";
    mIeee80211Header.writeParams(RADIO_PORT, ieee80211_seq);
    ieee80211_seq += 16;
    const auto injectionTime=mPcapTransmitter.injectPacket(mRadiotapHeader,mIeee80211Header,abstractWbPacket);
    nInjectedPackets++;
#ifdef ENABLE_ADVANCED_DEBUGGING
    pcapInjectionTime.add(injectionTime);
    if(pcapInjectionTime.getMax()>std::chrono::milliseconds (1)){
        std::cerr<<"Injecting PCAP packet took really long:"<<pcapInjectionTime.getAvgReadable()<<"\n";
        pcapInjectionTime.reset();
    }
#endif
}

void WBTransmitter::sendFecBlock(const uint64_t nonce,const uint8_t* payload,const std::size_t payloadSize) {
    //std::cout << "WBTransmitter::sendFecBlock"<<(int)wbDataPacket.payloadSize<<"\n";
    //const auto data= mEncryptor.makeEncryptedPacketIncludingHeader(wbDataPacket);
    //const auto encryptedData=mEncryptor.encryptWBDataPacket(wbDataPacket);
    const auto encryptedData=mEncryptor.encryptPacket(nonce,payload,payloadSize);
    WBDataHeader wbDataHeader(nonce);

    sendPacket({(const uint8_t*)&wbDataHeader,sizeof(WBDataHeader),encryptedData.data(),encryptedData.size()});
    //const auto encryptedWBDataPacket=mEncryptor.encryptWBDataPacket(wbDataPacket);
    //sendPacket((uint8_t*)&encryptedWBDataPacket.wbDataHeader,sizeof(WBDataHeader),encryptedWBDataPacket.payload,encryptedWBDataPacket.payloadSize);
#ifdef ENABLE_ADVANCED_DEBUGGING
    //LatencyTestingPacket latencyTestingPacket;
    //sendPacket((uint8_t*)&latencyTestingPacket,sizeof(latencyTestingPacket));
#endif
}

void WBTransmitter::sendSessionKey() {
    std::cout << "sendSessionKey()\n";
    sendPacket({(uint8_t *)&sessionKeyPacket, WBSessionKeyPacket::SIZE_BYTES});
}

void WBTransmitter::processInputPacket(const uint8_t *buf, size_t size) {
    //std::cout << "WBTransmitter::send_packet\n";
    // this calls a callback internally
    FECEncoder::encodePacket(buf,size);
    if(FECEncoder::resetOnOverflow()){
        // running out of sequence numbers should never happen during the lifetime of the TX instance
        mEncryptor.makeNewSessionKey(sessionKeyPacket.sessionKeyNonce, sessionKeyPacket.sessionKeyData);
        sendSessionKey();
    }
}

void WBTransmitter::loop() {
    std::array<uint8_t,MAX_PAYLOAD_SIZE> buf{};
    std::chrono::steady_clock::time_point session_key_announce_ts{};
    std::chrono::steady_clock::time_point log_ts{};
    // send the key a couple of times on startup to increase the likeliness it is received
    bool firstTime=true;
    // -1 would mean "flushing disabled"
    if(FLUSH_INTERVAL>std::chrono::milliseconds(0)){
        SocketHelper::setSocketReceiveTimeout(mInputSocket,FLUSH_INTERVAL);
    }else{
        SocketHelper::setSocketReceiveTimeout(mInputSocket,LOG_INTERVAL);
    }
    for(;;){
        // send the session key a couple of times on startup
        if(firstTime){
            for(int i=0;i<5;i++){
                sendSessionKey();
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }
            firstTime=false;
        }
        // only use a small timeout when the pipeline might need a flush
        //if(isAlreadyInFinishedState()){
        //    SocketHelper::setSocketReceiveTimeout(mInputSocket,LOG_INTERVAL);
        //}else{
        //    SocketHelper::setSocketReceiveTimeout(mInputSocket,FLUSH_INTERVAL);
        //}

        // we set the timeout earlier when creating the socket
        const ssize_t message_length = recvfrom(mInputSocket, buf.data(), MAX_PAYLOAD_SIZE, 0, nullptr, nullptr);
        if(std::chrono::steady_clock::now()>=log_ts){
            const auto runTimeMs=std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now()-INIT_TIME).count();
            std::cout<<runTimeMs<<"\tTX "<<nPacketsFromUdpPort<<":"<<nInjectedPackets<<"\n";
            log_ts= std::chrono::steady_clock::now() + WBTransmitter::LOG_INTERVAL;
        }
        if(message_length>0){
            nPacketsFromUdpPort++;
            const auto cur_ts=std::chrono::steady_clock::now();
            // send session key in SESSION_KEY_ANNOUNCE_DELTA intervals
            if ((cur_ts >= session_key_announce_ts) ) {
                // Announce session key
                sendSessionKey();
                session_key_announce_ts = cur_ts + SESSION_KEY_ANNOUNCE_DELTA;
            }
            processInputPacket(buf.data(), message_length);
        }else{
            if(errno==EAGAIN || errno==EWOULDBLOCK){
                // timeout
                if(FLUSH_INTERVAL.count()>0){
                    // smaller than 0 means no flush enabled
                    // else we didn't receive data for FLUSH_INTERVAL ms
                    // if nothing needs to be flushed, this call returns immediately
                    finishCurrentBlock();
                }
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
    // use -1 for no flush interval
    std::chrono::milliseconds flushInterval=std::chrono::milliseconds(-1);

    RadiotapHeader::UserSelectableParams params{20, false, 0, false, 1};

    std::string keypair = "drone.key";

    std::cout<<"MAX_PAYLOAD_SIZE:"<<MAX_PAYLOAD_SIZE<<"\n";

    while ((opt = getopt(argc, argv, "K:k:n:u:r:p:B:G:S:L:M:f:")) != -1) {
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
                params.bandwidth = atoi(optarg);
                break;
            case 'G':
                params.short_gi = (optarg[0] == 's' || optarg[0] == 'S');
                break;
            case 'S':
                params.stbc = atoi(optarg);
                break;
            case 'L':
                params.ldpc = atoi(optarg);
                break;
            case 'M':
                params.mcs_index = atoi(optarg);
                break;
            case 'f':
                flushInterval=std::chrono::milliseconds(atoi(optarg));
                break;
            default: /* '?' */
            show_usage:
                fprintf(stderr,
                        "Usage: %s [-K tx_key] [-k RS_K] [-n RS_N] [-u udp_port] [-p radio_port] [-B bandwidth] [-G guard_interval] [-S stbc] [-L ldpc] [-M mcs_index] [-f flushInterval(ms)] interface \n",
                        argv[0]);
                fprintf(stderr,
                        "Default: K='%s', k=%d, n=%d, udp_port=%d, radio_port=%d bandwidth=%d guard_interval=%s stbc=%d ldpc=%d mcs_index=%d flushInterval=%d\n",
                        keypair.c_str(), k, n, udp_port, radio_port,params.bandwidth,params.short_gi ? "short" : "long",params.stbc,params.ldpc,params.mcs_index,
                        (int)std::chrono::duration_cast<std::chrono::milliseconds>(flushInterval).count());
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
    RadiotapHeader radiotapHeader{params};

    //RadiotapHelper::debugRadiotapHeader((uint8_t*)&radiotapHeader,sizeof(RadiotapHeader));
    //RadiotapHelper::debugRadiotapHeader((uint8_t*)&OldRadiotapHeaders::u8aRadiotapHeader80211n, sizeof(OldRadiotapHeaders::u8aRadiotapHeader80211n));
    //RadiotapHelper::debugRadiotapHeader((uint8_t*)&OldRadiotapHeaders::u8aRadiotapHeader, sizeof(OldRadiotapHeaders::u8aRadiotapHeader));
    SchedulingHelper::setThreadParamsMaxRealtime();

    // Validate the user input regarding K,N
    if(k==0){
        // Use K=0 and N=0 to have no FEC correction combined with no "holding onto packets" on the RX.
        if(n!=0){
            std::cerr<<"Use K=0 only in combination with N=0.\n"
                       "This is an advanced option that not only disables FEC, but also disables the RX queue, reducing latency when working with multiple Receivers.\n"
                       "If you don't know what this means, use FEC_K==1 and FEC_N==1 for a similar effect.\n";
            exit(1);
        }
    }else{
        if(n < k){
            std::cerr<<"N must be bigger or equal to K\n";
            exit(1);
        }
    }

    try {
        std::shared_ptr<WBTransmitter> t = std::make_shared<WBTransmitter>(
                radiotapHeader, k, n, keypair, radio_port,udp_port, wlan,flushInterval);
        t->loop();
    } catch (std::runtime_error &e) {
        fprintf(stderr, "Error: %s\n", e.what());
        exit(1);
    }
    return 0;
}

