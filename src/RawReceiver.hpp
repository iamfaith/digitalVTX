//
// Created by consti10 on 21.12.20.
//

#ifndef WIFIBROADCAST_RAWRECEIVER_H
#define WIFIBROADCAST_RAWRECEIVER_H

#include "Helper.hpp"
#include "HelperSources/TimeHelper.hpp"
#include "Ieee80211Header.hpp"
#include "RadiotapHeader.hpp"

#include <functional>
#include <unordered_map>
#include <cstdint>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pcap/pcap.h>

// This is a single header-only file you can use to build your own wifibroadcast link

// stuff that helps for receiving data with pcap
namespace RawReceiverHelper{
    // call before pcap_activate
    static void iteratePcapTimestamps(pcap_t* ppcap){
        int* availableTimestamps;
        const int nTypes=pcap_list_tstamp_types(ppcap,&availableTimestamps);
        std::cout<<"N available timestamp types "<<nTypes<<"\n";
        for(int i=0;i<nTypes;i++){
            const char* name=pcap_tstamp_type_val_to_name(availableTimestamps[i]);
            const char* description=pcap_tstamp_type_val_to_description(availableTimestamps[i]);
            std::cout<<"Name: "<<std::string(name)<<" Description: "<<std::string(description)<<"\n";
            if(availableTimestamps[i]==PCAP_TSTAMP_HOST){
                std::cout<<"Setting timestamp to host\n";
                pcap_set_tstamp_type(ppcap,PCAP_TSTAMP_HOST);
            }
        }
        pcap_free_tstamp_types(availableTimestamps);
    }
    // copy paste from svpcom
    // I think this one opens the rx interface with pcap and then sets a filter such that only packets pass through for the selected radio port
    static pcap_t* openRxWithPcap(const std::string& wlan,const int radio_port){
        pcap_t* ppcap;
        char errbuf[PCAP_ERRBUF_SIZE];
        ppcap = pcap_create(wlan.c_str(), errbuf);
        if (ppcap == NULL) {
            throw std::runtime_error(StringFormat::convert("Unable to open interface %s in pcap: %s", wlan.c_str(), errbuf));
        }
        iteratePcapTimestamps(ppcap);
        if (pcap_set_snaplen(ppcap, 4096) != 0) throw std::runtime_error("set_snaplen failed");
        if (pcap_set_promisc(ppcap, 1) != 0) throw std::runtime_error("set_promisc failed");
        //if (pcap_set_rfmon(ppcap, 1) !=0) throw runtime_error("set_rfmon failed");
        if (pcap_set_timeout(ppcap, -1) != 0) throw std::runtime_error("set_timeout failed");
        //if (pcap_set_buffer_size(ppcap, 2048) !=0) throw runtime_error("set_buffer_size failed");
        // Important: Without enabling this mode pcap buffers quite a lot of packets starting with version 1.5.0 !
        // https://www.tcpdump.org/manpages/pcap_set_immediate_mode.3pcap.html
        if(pcap_set_immediate_mode(ppcap,true)!=0)throw std::runtime_error(StringFormat::convert("pcap_set_immediate_mode failed: %s", pcap_geterr(ppcap)));
        if (pcap_activate(ppcap) != 0) throw std::runtime_error(StringFormat::convert("pcap_activate failed: %s", pcap_geterr(ppcap)));
        if (pcap_setnonblock(ppcap, 1, errbuf) != 0) throw std::runtime_error(StringFormat::convert("set_nonblock failed: %s", errbuf));

        int link_encap = pcap_datalink(ppcap);
        struct bpf_program bpfprogram{};
        std::string program;
        switch (link_encap) {
            case DLT_PRISM_HEADER:
                std::cout<<wlan<<" has DLT_PRISM_HEADER Encap\n";
                program = StringFormat::convert("radio[0x4a:4]==0x13223344 && radio[0x4e:2] == 0x55%.2x", radio_port);
                break;

            case DLT_IEEE802_11_RADIO:
                std::cout<<wlan<<" has DLT_IEEE802_11_RADIO Encap\n";
                program = StringFormat::convert("ether[0x0a:4]==0x13223344 && ether[0x0e:2] == 0x55%.2x", radio_port);
                break;
            default:
                throw std::runtime_error(StringFormat::convert("unknown encapsulation on %s", wlan.c_str()));
        }
        if (pcap_compile(ppcap, &bpfprogram, program.c_str(), 1, 0) == -1) {
            throw std::runtime_error(StringFormat::convert("Unable to compile %s: %s", program.c_str(), pcap_geterr(ppcap)));
        }
        if (pcap_setfilter(ppcap, &bpfprogram) == -1) {
            throw std::runtime_error(StringFormat::convert("Unable to set filter %s: %s", program.c_str(), pcap_geterr(ppcap)));
        }
        pcap_freecode(&bpfprogram);
        return ppcap;
    }
    struct RssiForAntenna{
        // which antenna the value refers to
        const uint8_t antennaIdx;
        // https://www.radiotap.org/fields/Antenna%20signal.html
        const int8_t rssi;
    };
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

// This class listens for WIFI data on the specified wlan for wifi packets with the right RADIO_PORT
// Processing of data is done by the callback
// It uses a slightly complicated pattern:
// 1) check if data is available via the fd
// 2) then call loop_iter().
// loop_iter loops over all packets for this wifi card that are not processed yet, then returns.
class PcapReceiver {
public:
    // this callback is called with the received packet from pcap
    typedef std::function<void(const uint8_t wlan_idx,const pcap_pkthdr& hdr,const uint8_t* pkt)> PROCESS_PACKET_CALLBACK;
    PcapReceiver(const std::string& wlan, int wlan_idx, int radio_port,PROCESS_PACKET_CALLBACK callback): WLAN_IDX(wlan_idx),RADIO_PORT(radio_port), mCallback(callback){
        ppcap=RawReceiverHelper::openRxWithPcap(wlan, RADIO_PORT);
        fd = pcap_get_selectable_fd(ppcap);
    }

    ~PcapReceiver(){
        close(fd);
        pcap_close(ppcap);
    }
    // loop receiving data from this interface until no more data is available
    void loop_iter() {
        // loop while incoming queue is not empty
        int nPacketsPolledUntilQueueWasEmpty=0;
        for (;;){
            struct pcap_pkthdr hdr{};
            const uint8_t *pkt = pcap_next(ppcap, &hdr);
            if (pkt == nullptr) {
#ifdef ENABLE_ADVANCED_DEBUGGING
                nOfPacketsPolledFromPcapQueuePerIteration.add(nPacketsPolledUntilQueueWasEmpty);
                std::cout<<"nOfPacketsPolledFromPcapQueuePerIteration: "<<nOfPacketsPolledFromPcapQueuePerIteration.getAvgReadable()<<"\n";
                nOfPacketsPolledFromPcapQueuePerIteration.reset();
#endif
                break;
            }
            timeForParsingPackets.start();
            mCallback(WLAN_IDX,hdr,pkt);
            timeForParsingPackets.stop();
#ifdef ENABLE_ADVANCED_DEBUGGING
            // how long the cpu spends on agg.processPacket
            timeForParsingPackets.printInIntervalls(std::chrono::seconds(1));
#endif
            nPacketsPolledUntilQueueWasEmpty++;
        }
    }

    int getfd() const { return fd; }

public:
    // the wifi interface this receiver listens on (not the radio port)
    const int WLAN_IDX;
    // the radio port it filters pacp packets for
    const int RADIO_PORT;
public:
    // this callback is called with valid data when doing loop_iter()
    const PROCESS_PACKET_CALLBACK mCallback;
    // this fd is created by pcap
    int fd;
    pcap_t *ppcap;
    // measures the cpu time spent on the callback
    Chronometer timeForParsingPackets{"PP"};
    // If each iteration pulls too many packets out your CPU is most likely too slow
    BaseAvgCalculator<int> nOfPacketsPolledFromPcapQueuePerIteration;
};

#endif //WIFIBROADCAST_RAWRECEIVER_H
