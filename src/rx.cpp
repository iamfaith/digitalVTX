
// Copyright (C) 2017, 2018 Vasily Evseenko <svpcom@p2ptech.org>
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
#include "RawReceiver.hpp"
#include "rx.hpp"
#include "wifibroadcast.hpp"
#include "HelperSources/SchedulingHelper.hpp"
#include <cassert>
#include <cstdio>
#include <cinttypes>
#include <unistd.h>
#include <pcap/pcap.h>
#include <poll.h>
#include <memory>
#include <string>
#include <chrono>
#include <sstream>


Aggregator::Aggregator(const std::string &client_addr, int client_udp_port,uint8_t radio_port,const std::string &keypair) :
FECDecoder(),
CLIENT_UDP_PORT(client_udp_port),
RADIO_PORT(radio_port),
mDecryptor(keypair){
    sockfd = SocketHelper::open_udp_socket_for_tx(client_addr,client_udp_port);
    // Default to 8,12
    //mFecDecoder=std::make_unique<FECDecoder>(8,12);
    FECDecoder::mSendDecodedPayloadCallback=std::bind(&Aggregator::sendPacketViaUDP, this, std::placeholders::_1, std::placeholders::_2);
    //
}

Aggregator::~Aggregator() {
    close(sockfd);
}

void Aggregator::dump_stats() {
    // first forward to OpenHD
    openHdStatisticsWriter.writeStats({
                                              count_p_all, count_p_decryption_err, count_p_decryption_ok, count_p_fec_recovered, count_p_lost, count_p_bad, rssiForWifiCard
    });
    //timestamp in ms
    const uint64_t runTime=std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now()-INIT_TIME).count();
    for(auto& wifiCard : rssiForWifiCard){
        // no new rssi values for this card since the last call
        if(wifiCard.count_all==0)continue;
        std::cout<<"RSSI Count|Min|Max|Avg:\t"<<(int)wifiCard.count_all<<":"<<(int)wifiCard.rssi_min<<":"<<(int)wifiCard.rssi_max<<":"<<(int)wifiCard.getAverage()<<"\n";
        wifiCard.reset();
    }
    std::stringstream ss;
    ss << runTime << "\tPKT\t\t" << count_p_all << ":" << count_p_decryption_ok << ":" << count_p_decryption_err << ":" << count_p_fec_recovered << ":" << count_p_lost << ":" << count_p_lost << ":";
    std::cout<<ss.str()<<"\n";
    // it is actually much more understandable when I use the absolute values for the logging
#ifdef ENABLE_ADVANCED_DEBUGGING
    std::cout<<"avgPcapToApplicationLatency: "<<avgPcapToApplicationLatency.getAvgReadable()<<"\n";
    //std::cout<<"avgLatencyBeaconPacketLatency"<<avgLatencyBeaconPacketLatency.getAvgReadable()<<"\n";
    //std::cout<<"avgLatencyBeaconPacketLatencyX:"<<avgLatencyBeaconPacketLatency.getNValuesLowHigh(20)<<"\n";
    //std::cout<<"avgLatencyPacketInQueue"<<avgLatencyPacketInQueue.getAvgReadable()<<"\n";
#endif
}

void Aggregator::processPacket(const uint8_t WLAN_IDX,const pcap_pkthdr& hdr,const uint8_t* pkt){
#ifdef ENABLE_ADVANCED_DEBUGGING
    const auto tmp=GenericHelper::timevalToTimePointSystemClock(hdr.ts);
    const auto latency=std::chrono::system_clock::now() -tmp;
    avgPcapToApplicationLatency.add(latency);
#endif
    count_p_all++;
    // The radio capture header precedes the 802.11 header.
    const auto parsedPacket=RawReceiverHelper::processReceivedPcapPacket(hdr, pkt);
    if(parsedPacket==std::nullopt){
        std::cerr<< "Discarding packet due to pcap parsing error!\n";
        count_p_bad++;
        return;
    }
    if(parsedPacket->frameFailedFCSCheck){
        std::cerr<< "Discarding packet due to bad FCS!\n";
        count_p_bad++;
        return;
    }
    if(!parsedPacket->ieee80211Header->isDataFrame()){
        // we only process data frames
        std::cerr<<"Got packet that is not a data packet"<<(int)parsedPacket->ieee80211Header->getFrameControl()<<"\n";
        count_p_bad++;
        return;
    }
    if(parsedPacket->ieee80211Header->getRadioPort()!=RADIO_PORT) {
        // If we have the proper filter on pcap only packets with the right radiotap port should pass through
        std::cerr<<"Got packet with wrong radio port "<<(int)parsedPacket->ieee80211Header->getRadioPort()<<"\n";
        //RadiotapHelper::debugRadiotapHeader(pkt,hdr.caplen);
        count_p_bad++;
        return;
    }
    // All these edge cases should NEVER happen if using a proper tx/rx setup and the wifi driver isn't complete crap
    if(parsedPacket->payloadSize<=0){
        std::cerr<<"Discarding packet due to no actual payload !\n";
        count_p_bad++;
        return;
    }
    if (parsedPacket->payloadSize > MAX_FORWARDER_PACKET_SIZE) {
        std::cerr<<"Discarding packet due to payload exceeding max "<<(int)parsedPacket->payloadSize<<"\n";
        count_p_bad++;
        return;
    }
    if(parsedPacket->allAntennaValues.size()>MAX_N_ANTENNAS_PER_WIFI_CARD){
        std::cerr<<"Wifi card with "<<parsedPacket->allAntennaValues.size()<<" antennas\n";
    }
    auto& thisWifiCard=rssiForWifiCard[WLAN_IDX];
    for(const auto& value : parsedPacket->allAntennaValues){
        // don't care from which antenna the value came
        thisWifiCard.addRSSI(value.rssi);
    }

    //RawTransmitterHelper::writeAntennaStats(antenna_stat, WLAN_IDX, parsedPacket->antenna, parsedPacket->rssi);
    //const Ieee80211Header* tmpHeader=parsedPacket->ieee80211Header;
    //std::cout<<"RADIO_PORT"<<(int)tmpHeader->getRadioPort()<<" IEEE_SEQ_NR "<<(int)tmpHeader->getSequenceNumber()<<"\n";
    //std::cout<<"FrameControl:"<<(int)tmpHeader->getFrameControl()<<"\n";
    //std::cout<<"DurationOrConnectionId:"<<(int)tmpHeader->getDurationOrConnectionId()<<"\n";

    // now to the actual payload
    const uint8_t *payload=parsedPacket->payload;
    const size_t payloadSize=parsedPacket->payloadSize;
    if(payload[0]==WFB_PACKET_DATA){
        if (payloadSize < sizeof(WBDataHeader) + sizeof(FECDataHeader)) {
            std::cerr<<"short packet (fec header)\n";
            count_p_bad++;
            return;
        }
        // FEC data or FEC correction packet
        //WBDataPacket encryptedWbDataPacket=WBDataPacket::createFromRawMemory(payload, payloadSize);
        const WBDataHeader& wbDataHeader=*((WBDataHeader*)payload);
        assert(wbDataHeader.packet_type==WFB_PACKET_DATA);

        const auto decryptedPayload=mDecryptor.decryptPacket(wbDataHeader.nonce,payload,payloadSize);
        if(decryptedPayload == std::nullopt){
            std::cerr << "unable to decrypt packet (block_idx,fragment_idx):" << wbDataHeader.getBlockIdx() << "," << (int)wbDataHeader.getFragmentIdx() << "\n";
            count_p_decryption_err ++;
            return;
        }

        count_p_decryption_ok++;

        assert(decryptedPayload->size() <= MAX_FEC_PAYLOAD);

        if(!FECDecoder::validateAndProcessPacket(wbDataHeader.nonce, *decryptedPayload)){
            count_p_bad++;
        }
    }else if(payload[0]==WFB_PACKET_KEY) {
        if (payloadSize != WBSessionKeyPacket::SIZE_BYTES) {
            std::cerr << "invalid session key packet\n";
            count_p_bad++;
            return;
        }
        WBSessionKeyPacket &sessionKeyPacket = *((WBSessionKeyPacket *) parsedPacket->payload);
        if (mDecryptor.onNewPacketSessionKeyData(sessionKeyPacket.sessionKeyNonce, sessionKeyPacket.sessionKeyData)) {
            // We got a new session key (aka a session key that has not been received yet)
            count_p_decryption_ok++;
            FECDecoder::resetNewSession(sessionKeyPacket.FEC_N_PRIMARY_FRAGMENTS,
                                        sessionKeyPacket.FEC_N_PRIMARY_FRAGMENTS +
                                        sessionKeyPacket.FEC_N_SECONDARY_FRAGMENTS);
        } else {
            count_p_decryption_ok++;
        }
        return;
    }
#ifdef ENABLE_ADVANCED_DEBUGGING
    else if(payload[0]==WFB_PACKET_LATENCY_BEACON){
        // for testing only. It won't work if the tx and rx are running on different systems
            assert(payloadSize==sizeof(LatencyTestingPacket));
            const LatencyTestingPacket* latencyTestingPacket=(LatencyTestingPacket*)payload;
            const auto timestamp=std::chrono::time_point<std::chrono::steady_clock>(std::chrono::nanoseconds(latencyTestingPacket->timestampNs));
            const auto latency=std::chrono::steady_clock::now()-timestamp;
            //std::cout<<"Packet latency on this system is "<<std::chrono::duration_cast<std::chrono::nanoseconds>(latency).count()<<"\n";
            avgLatencyBeaconPacketLatency.add(latency);
    }
#endif
    else{
        std::cerr<<"Unknown packet type "<<(int)payload[0]<<" \n";
        count_p_bad += 1;
        return;
    }
}

void Aggregator::flushFecPipeline() {
    FECDecoder::flushRxRing();
}

int main(int argc, char *const *argv) {
    int opt;
    uint8_t radio_port = 1;
    std::chrono::milliseconds log_interval{1000};
    // use -1 for no flush interval
    std::chrono::milliseconds flush_interval{-1};
    int client_udp_port = 5600;
    std::string client_addr = "127.0.0.1";
    std::string keypair = "gs.key";

    while ((opt = getopt(argc, argv, "K:k:n:c:u:p:l:f:")) != -1) {
        switch (opt) {
            case 'K':
                keypair = optarg;
                break;
            case 'c':
                client_addr = std::string(optarg);
                break;
            case 'u':
                client_udp_port = atoi(optarg);
                break;
            case 'p':
                radio_port = atoi(optarg);
                break;
            case 'l':
                log_interval = std::chrono::milliseconds(atoi(optarg));
                break;
            case 'f':
                flush_interval=std::chrono::milliseconds(atoi(optarg));
                break;
            default: /* '?' */
            show_usage:
                fprintf(stderr,
                        "Local receiver: %s [-K rx_key] [-c client_addr] [-u client_port] [-p radio_port] [-l log_interval(ms)] [-f flush_interval(ms)] interface1 [interface2] ...\n",
                        argv[0]);
                fprintf(stderr, "Default: K='%s', connect=%s:%d, radio_port=%d, log_interval=%d flush_interval=%d\n",
                        keypair.c_str(),client_addr.c_str(), client_udp_port, radio_port,
                        (int)std::chrono::duration_cast<std::chrono::milliseconds>(log_interval).count(),(int)std::chrono::duration_cast<std::chrono::milliseconds>(flush_interval).count());
                fprintf(stderr, "WFB version "
                WFB_VERSION
                "\n");
                exit(1);
        }
    }
    const int nRxInterfaces=argc-optind;
    if(nRxInterfaces>MAX_RX_INTERFACES){
        std::cout<<"Too many RX interfaces "<<nRxInterfaces<<"\n";
        goto show_usage;
    }
    SchedulingHelper::setThreadParamsMaxRealtime();

    std::vector<std::string> rxInterfaces;
    for (int i = 0; i < nRxInterfaces; i++) {
        rxInterfaces.emplace_back(argv[optind + i]);
    }
    try {
        std::shared_ptr<Aggregator> agg=std::make_shared<Aggregator>(client_addr, client_udp_port,radio_port, keypair);
        //radio_loop(agg,rxInterfaces, radio_port, log_interval,flush_interval);
        //std::unique_ptr<MultiRxPcapReceiver> mMultiRxPcapReceiver=std::make_unique<MultiRxPcapReceiver>(rxInterfaces,)
        MultiRxPcapReceiver receiver(rxInterfaces,radio_port,log_interval,flush_interval,
                                     std::bind(&Aggregator::processPacket, agg.get(), std::placeholders::_1, std::placeholders::_2, std::placeholders::_3),
                                     std::bind(&Aggregator::dump_stats, agg.get()),
                                     std::bind(&Aggregator::flushFecPipeline, agg.get()));
        receiver.loop();
    } catch (std::runtime_error &e) {
        fprintf(stderr, "Error: %s\n", e.what());
        exit(1);
    }
    return 0;
}
