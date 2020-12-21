
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

namespace RawReceiverHelper{
    struct ParsedRxPcapPacket{
        // Size can be anything from size=1 to size== N where N is the number of Antennas of this adapter
        const std::vector<RssiForAntenna> allAntennaValues;
        const Ieee80211Header* ieee80211Header;
        const uint8_t* payload;
        const std::size_t payloadSize;
        // Atheros forwards frames even though the fcs check failed ( this packet is corrupted)
        const bool frameFailedFCSCheck;
    };
    // Returns std::nullopt if radiotap was unable to parse the header
    // else return the *parsed information*
    // To avoid confusion it might help to treat this method as a big black Box :)
    static std::optional<ParsedRxPcapPacket> processReceivedPcapPacket(const pcap_pkthdr& hdr, const uint8_t *pkt){
        int pktlen = hdr.caplen;
        // Copy the value of this flag once present and process it after the loop is done
        uint8_t tmpCopyOfIEEE80211_RADIOTAP_FLAGS = 0;
        //RadiotapHelper::debugRadiotapHeader(pkt, pktlen);
        struct ieee80211_radiotap_iterator iterator{};
        // With AR9271 I get 39 as length of the radio-tap header
        // With my internal laptop wifi chip I get 36 as length of the radio-tap header.
        int ret = ieee80211_radiotap_iterator_init(&iterator, (ieee80211_radiotap_header *) pkt, pktlen, NULL);
        uint8_t currentAntenna=0;
        // not confirmed yet, but one pcap packet might include stats for multiple antennas
        std::vector<RssiForAntenna> allAntennaValues;
        while (ret == 0 ) {
            ret = ieee80211_radiotap_iterator_next(&iterator);
            if (ret){
                continue;
            }
            /* see if this argument is something we can use */
            switch (iterator.this_arg_index) {
                 /*case IEEE80211_RADIOTAP_RATE:
                     // radiotap "rate" u8 is in
                     // 500kbps units, eg, 0x02=1Mbps
                 {
                     uint8_t pkt_rate = (*(uint8_t*)(iterator.this_arg))/2;
                     int rateInMbps=pkt_rate*2;
                     std::cout<<"Packet rate is "<<rateInMbps<<"\n";
                 }
                     break;*/
                case IEEE80211_RADIOTAP_ANTENNA:
                    // RADIOTAP_DBM_ANTSIGNAL should come directly afterwards
                    currentAntenna=iterator.this_arg[0];
                    break;
                case IEEE80211_RADIOTAP_DBM_ANTSIGNAL:
                    allAntennaValues.push_back({currentAntenna,*((int8_t*)iterator.this_arg)});
                    break;
                case IEEE80211_RADIOTAP_FLAGS:
                    tmpCopyOfIEEE80211_RADIOTAP_FLAGS = *(uint8_t *) (iterator.this_arg);
                    break;
                default:
                    break;
            }
        }  /* while more rt headers */
        if (ret != -ENOENT) {
            //std::cerr<<"Error parsing radiotap header!\n";
            return std::nullopt;
        }
        bool frameFailedFcsCheck=false;
        if (tmpCopyOfIEEE80211_RADIOTAP_FLAGS & IEEE80211_RADIOTAP_F_BADFCS) {
            //std::cerr<<"Got packet with bad fsc\n";
            frameFailedFcsCheck=true;
        }
        // the fcs is at the end of the packet
        if (tmpCopyOfIEEE80211_RADIOTAP_FLAGS & IEEE80211_RADIOTAP_F_FCS) {
            //std::cout<<"Packet has IEEE80211_RADIOTAP_F_FCS";
            pktlen -= 4;
        }
#ifdef ENABLE_ADVANCED_DEBUGGING
        //std::cout<<RadiotapFlagsToString::flagsIEEE80211_RADIOTAP_MCS(mIEEE80211_RADIOTAP_MCS)<<"\n";
        //std::cout<<RadiotapFlagsToString::flagsIEEE80211_RADIOTAP_FLAGS(mIEEE80211_RADIOTAP_FLAGS)<<"\n";
        // With AR9271 I get 39 as length of the radio-tap header
        // With my internal laptop wifi chip I get 36 as length of the radio-tap header
        //std::cout<<"iterator._max_length was "<<iterator._max_length<<"\n";
#endif
        //assert(iterator._max_length==hdr.caplen);
        /* discard the radiotap header part */
        pkt += iterator._max_length;
        pktlen -= iterator._max_length;
        //
        const Ieee80211Header* ieee80211Header=(Ieee80211Header*)pkt;
        const uint8_t* payload=pkt+Ieee80211Header::SIZE_BYTES;
        const std::size_t payloadSize=(std::size_t)pktlen-Ieee80211Header::SIZE_BYTES;
        return ParsedRxPcapPacket{allAntennaValues,ieee80211Header,payload,payloadSize,frameFailedFcsCheck};
    }
}

Aggregator::Aggregator(const std::string &client_addr, int client_udp_port,uint8_t radio_port, int k, int n, const std::string &keypair) :
FECDecoder(k,n),
CLIENT_UDP_PORT(client_udp_port),
RADIO_PORT(radio_port),
mDecryptor(keypair){
    sockfd = SocketHelper::open_udp_socket_for_tx(client_addr,client_udp_port);
    callback=std::bind(&Aggregator::sendPacketViaUDP, this, std::placeholders::_1,std::placeholders::_2);
}

Aggregator::~Aggregator() {
    close(sockfd);
}

void Aggregator::dump_stats() {
    // first forward to OpenHD
    openHdStatisticsWriter.writeStats({
        count_p_all,count_p_dec_err,count_p_dec_ok,count_p_fec_recovered,count_p_lost,count_p_bad,rssiForWifiCard
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
    ss<<runTime<<"\tPKT\t\t"<<count_p_all<<":"<<count_p_all<<":"<<count_p_dec_err<<":"<<count_p_dec_ok<<":"<<count_p_fec_recovered<<":"<<count_p_lost<<":"<<count_p_lost<<":";
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
        return;
    }
    if(parsedPacket->ieee80211Header->getRadioPort()!=RADIO_PORT) {
        // If we have the proper filter on pcap only packets with the right radiotap port should pass through
        std::cerr<<"Got packet with wrong radio port "<<(int)parsedPacket->ieee80211Header->getRadioPort()<<"\n";
        //RadiotapHelper::debugRadiotapHeader(pkt,hdr.caplen);
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
    const Ieee80211Header* tmpHeader=parsedPacket->ieee80211Header;
    //std::cout<<"RADIO_PORT"<<(int)tmpHeader->getRadioPort()<<" IEEE_SEQ_NR "<<(int)tmpHeader->getSequenceNumber()<<"\n";
    //std::cout<<"FrameControl:"<<(int)tmpHeader->getFrameControl()<<"\n";
    //std::cout<<"DurationOrConnectionId:"<<(int)tmpHeader->getDurationOrConnectionId()<<"\n";

    // now to the actual payload
    const uint8_t *payload=parsedPacket->payload;
    const size_t payloadSize=parsedPacket->payloadSize;
    switch (payload[0]) {
        case WFB_PACKET_DATA:
            if (payloadSize < sizeof(WBDataHeader) + sizeof(FECDataHeader)) {
                std::cerr<<"short packet (fec header)\n";
                count_p_bad++;
                return;
            }
            break;
        case WFB_PACKET_KEY:
            if (payloadSize != WBSessionKeyPacket::SIZE_BYTES) {
                std::cerr<<"invalid session key packet\n";
                count_p_bad++;
                return;
            }
            if (mDecryptor.onNewPacketWfbKey(payload)) {
                count_p_dec_ok++;
                FECDecoder::reset();
            } else {
                count_p_dec_ok++;
            }
            return;
        case WFB_PACKET_LATENCY_BEACON:{
#ifdef ENABLE_ADVANCED_DEBUGGING
            // for testing only. It won't work if the tx and rx are running on different systems
            assert(payloadSize==sizeof(LatencyTestingPacket));
            const LatencyTestingPacket* latencyTestingPacket=(LatencyTestingPacket*)payload;
            const auto timestamp=std::chrono::time_point<std::chrono::steady_clock>(std::chrono::nanoseconds(latencyTestingPacket->timestampNs));
            const auto latency=std::chrono::steady_clock::now()-timestamp;
            //std::cout<<"Packet latency on this system is "<<std::chrono::duration_cast<std::chrono::nanoseconds>(latency).count()<<"\n";
            avgLatencyBeaconPacketLatency.add(latency);
#endif
        }
            return;
        default:
            std::cerr<<"Unknown packet type "<<(int)payload[0]<<" \n";
            count_p_bad += 1;
            return;
    }
    // FEC data or FEC correction packet
    WBDataPacket encryptedWbDataPacket=WBDataPacket::createFromRawMemory(payload, payloadSize);

    const auto decryptedPayload=mDecryptor.decryptPacket(encryptedWbDataPacket);
    if(decryptedPayload == std::nullopt){
        std::cerr << "unable to decrypt packet (block_idx,fragment_idx):" << encryptedWbDataPacket.wbDataHeader.getBlockIdx() << "," << (int)encryptedWbDataPacket.wbDataHeader.getFragmentIdx() << "\n";
        count_p_dec_err ++;
        return;
    }

    count_p_dec_ok++;

    assert(decryptedPayload->size() <= MAX_FEC_PAYLOAD);

    if(!FECDecoder::validateAndProcessPacket(encryptedWbDataPacket.wbDataHeader, *decryptedPayload)){
        count_p_bad++;
    }
}


void
radio_loop(std::shared_ptr<Aggregator> agg,const std::vector<std::string> rxInterfaces,const int radio_port,const std::chrono::milliseconds log_interval,const std::chrono::milliseconds flush_interval) {
    const int N_RECEIVERS = rxInterfaces.size();
    struct pollfd fds[N_RECEIVERS];
    PcapReceiver *rx[N_RECEIVERS];

    memset(fds, '\0', sizeof(fds));
    std::stringstream ss;
    ss<<"WB-RX Forwarding to: "<<agg->CLIENT_UDP_PORT<<" Assigned ID: "<<radio_port<<" FLUSH_INTERVAL(ms):"<<(int)flush_interval.count()<<" Assigned WLAN(s):";

    for (int i = 0; i < N_RECEIVERS; i++) {
        rx[i] = new PcapReceiver(rxInterfaces[i], i, radio_port, std::bind(&Aggregator::processPacket,agg.get(), std::placeholders::_1,std::placeholders::_2,std::placeholders::_3));
        fds[i].fd = rx[i]->getfd();
        fds[i].events = POLLIN;
        ss<<rxInterfaces[i]<<" ";
    }
    std::cout<<ss.str()<<"\n";
    if(flush_interval>log_interval){
        std::cerr<<"Please use a flush interval smaller than the log interval\n";
    }
    if(flush_interval==std::chrono::milliseconds(0)){
        std::cerr<<"Please do not use a flush interval of 0 (this hogs the cpu)\n";
    }
    std::chrono::steady_clock::time_point log_send_ts{};
    for (;;) {
        auto cur_ts=std::chrono::steady_clock::now();
        //const int timeoutMS=log_send_ts > cur_ts ? (int)std::chrono::duration_cast<std::chrono::milliseconds>(log_send_ts - cur_ts).count() : 0;
        const int timeoutMS=flush_interval.count()>0 ? std::chrono::duration_cast<std::chrono::milliseconds>(flush_interval).count() : std::chrono::duration_cast<std::chrono::milliseconds>(log_interval).count();
        int rc = poll(fds, N_RECEIVERS,timeoutMS);

        if (rc < 0) {
            if (errno == EINTR || errno == EAGAIN) continue;
            throw std::runtime_error(StringFormat::convert("Poll error: %s", strerror(errno)));
        }

        cur_ts = std::chrono::steady_clock::now();

        if (cur_ts >= log_send_ts) {
            agg->dump_stats();
            log_send_ts = std::chrono::steady_clock::now() + log_interval;
        }

        if (rc == 0){
            // timeout expired
            if(flush_interval.count()>0){
                // smaller than 0 means no flush enabled
                // else we didn't receive data for FLUSH_INTERVAL ms
                agg->flushRxRing();
            }
            continue;
        }
        for (int i = 0; rc > 0 && i < N_RECEIVERS; i++) {
            if (fds[i].revents & (POLLERR | POLLNVAL)) {
                throw std::runtime_error("socket error!");
            }
            if (fds[i].revents & POLLIN) {
                rx[i]->loop_iter();
                rc -= 1;
            }
        }
    }
}


int main(int argc, char *const *argv) {
    int opt;
    uint8_t k = 8, n = 12, radio_port = 1;
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
            case 'k':
                k = atoi(optarg);
                break;
            case 'n':
                n = atoi(optarg);
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
                        "Local receiver: %s [-K rx_key] [-k RS_K] [-n RS_N] [-c client_addr] [-u client_port] [-p radio_port] [-l log_interval(ms)] [-f flush_interval(ms)] interface1 [interface2] ...\n",
                        argv[0]);
                fprintf(stderr, "Default: K='%s', k=%d, n=%d, connect=%s:%d, radio_port=%d, log_interval=%d flush_interval=%d\n",
                        keypair.c_str(), k, n, client_addr.c_str(), client_udp_port, radio_port,
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
        rxInterfaces.push_back(argv[optind + i]);
    }
    try {
        std::shared_ptr<Aggregator> agg=std::make_shared<Aggregator>(client_addr, client_udp_port,radio_port, k, n, keypair);
        radio_loop(agg,rxInterfaces, radio_port, log_interval,flush_interval);
    } catch (std::runtime_error &e) {
        fprintf(stderr, "Error: %s\n", e.what());
        exit(1);
    }
    return 0;
}
