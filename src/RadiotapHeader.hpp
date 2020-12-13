#ifndef __WIFIBROADCAST_RADIOTAP_HEADER_HPP__
#define __WIFIBROADCAST_RADIOTAP_HEADER_HPP__

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <resolv.h>
#include <string.h>
#include <utime.h>
#include <unistd.h>
#include <getopt.h>
#include <pcap.h>
#include <endian.h>
#include <fcntl.h>
#include <time.h>
#include <sys/mman.h>
#include <sodium.h>
#include <endian.h>
#include <string>
#include <vector>
#include <chrono>
#include <sstream>
#include <iostream>
#include "ExternalCSources/radiotap_iter.h"

extern "C"{
#include "ExternalCSources/radiotap.h"
};

// Default is MCS#1 -- QPSK 1/2 40MHz SGI -- 30 Mbit/s
// MCS_FLAGS = (IEEE80211_RADIOTAP_MCS_BW_40 | IEEE80211_RADIOTAP_MCS_SGI | (IEEE80211_RADIOTAP_MCS_STBC_1 << IEEE80211_RADIOTAP_MCS_STBC_SHIFT))

//#define MCS_KNOWN (IEEE80211_RADIOTAP_MCS_HAVE_MCS | IEEE80211_RADIOTAP_MCS_HAVE_BW | IEEE80211_RADIOTAP_MCS_HAVE_GI | IEEE80211_RADIOTAP_MCS_HAVE_STBC | IEEE80211_RADIOTAP_MCS_HAVE_FEC)

// Wrapper around the radiotap header (declared as raw array initially)
// Used for injecting packets with the right parameters
class RadiotapHeader{
public:
    static constexpr uint8_t MY_RADIOTAP_FLAG_MCS_HAVE=(IEEE80211_RADIOTAP_MCS_HAVE_MCS | IEEE80211_RADIOTAP_MCS_HAVE_BW | IEEE80211_RADIOTAP_MCS_HAVE_GI | IEEE80211_RADIOTAP_MCS_HAVE_STBC | IEEE80211_RADIOTAP_MCS_HAVE_FEC);
    static constexpr auto SIZE_BYTES=13;
    // offset of MCS_FLAGS and MCS index
    static constexpr const auto MCS_FLAGS_OFF=11;
    static constexpr const auto MCS_IDX_OFF=12;
    // raw data buffer
    // unfortunately I do not know what these 'default bytes' mean
    std::array<uint8_t,SIZE_BYTES> data={
            0x00, 0x00, // <-- radiotap version
            0x0d, 0x00, // <- radiotap header length
            0x00, 0x80, 0x08, 0x00, // <-- radiotap present flags:  RADIOTAP_TX_FLAGS + RADIOTAP_MCS
            0x08, 0x00,  // RADIOTAP_F_TX_NOACK
            MY_RADIOTAP_FLAG_MCS_HAVE ,    // for everything in ieee80211_radiotap_mcs_have
            0x00,              // for everything in ieee80211_radiotap_mcs_flags
            0x00               //mcs_index, doesn't work with Atheros properly
    };
    // default constructor
    RadiotapHeader()=default;
    // these are the params in use by OpenHD right now
    struct RadiotapHeaderParams{
        int bandwidth;
        int short_gi;
        int stbc;
        int ldpc;
        int mcs_index;
    };
    // write the user-selected parameters
    void writeParams(const RadiotapHeaderParams& params){
        uint8_t flags = 0;
        switch(params.bandwidth) {
            case 20:
                flags |= IEEE80211_RADIOTAP_MCS_BW_20;
                break;
            case 40:
                flags |= IEEE80211_RADIOTAP_MCS_BW_40;
                break;
            default:
                std::cerr<<"Unsupported bandwidth: "<<params.bandwidth;
                exit(1);
        }
        if(params.short_gi){
            flags |= IEEE80211_RADIOTAP_MCS_SGI;
        }
        switch(params.stbc) {
            case 0:
                break;
            case 1:
                flags |= (IEEE80211_RADIOTAP_MCS_STBC_1 << IEEE80211_RADIOTAP_MCS_STBC_SHIFT);
                break;
            case 2:
                flags |= (IEEE80211_RADIOTAP_MCS_STBC_2 << IEEE80211_RADIOTAP_MCS_STBC_SHIFT);
                break;
            case 3:
                flags |= (IEEE80211_RADIOTAP_MCS_STBC_3 << IEEE80211_RADIOTAP_MCS_STBC_SHIFT);
                break;
            default:
                std::cerr<<"Unsupported STBC type: "<<params.stbc;
                exit(1);
        }
        if(params.ldpc){
            flags |= IEEE80211_RADIOTAP_MCS_FEC_LDPC;
        }
        data[MCS_FLAGS_OFF]=flags;
        data[MCS_IDX_OFF]=params.mcs_index;
    }
    void writeParams(int bandwidth,int short_gi,int stbc,int ldpc,int mcs_index){
        writeParams({bandwidth,short_gi,stbc,ldpc,mcs_index});
    }
    const uint8_t* getData()const{
        return data.data();
    }
    constexpr std::size_t getSize()const{
        return data.size();
    }
}__attribute__ ((packed));
static_assert(sizeof(RadiotapHeader) == RadiotapHeader::SIZE_BYTES, "ALWAYS TRUE");

namespace RadiotapHelper{
    std::string flagsIEEE80211_RADIOTAP_FLAGS(uint8_t flags){
        std::stringstream ss;
        ss<<"All IEEE80211_RADIOTAP flags: [";
        if(flags & IEEE80211_RADIOTAP_F_CFP){
            ss<<"CFP,";
        }
        if(flags & IEEE80211_RADIOTAP_F_SHORTPRE){
            ss<<"SHORTPRE,";
        }
        if(flags & IEEE80211_RADIOTAP_F_WEP){
            ss<<"WEP,";
        }
        if(flags & IEEE80211_RADIOTAP_F_FRAG){
            ss<<"FRAG,";
        }
        if(flags & IEEE80211_RADIOTAP_F_FCS){
            ss<<"FCS,";
        }
        if(flags & IEEE80211_RADIOTAP_F_DATAPAD){
            ss<<"DATAPAD,";
        }
        if(flags & IEEE80211_RADIOTAP_F_BADFCS){
            ss<<"BADFCS";
        }
        ss<<"]";
        return ss.str();
    }
    std::string flagsIEEE80211_RADIOTAP_MCS(const uint8_t flags) {
        std::stringstream ss;
        ss<<"All IEEE80211_RADIOTAP_MCS flags: [";
        if(flags &  IEEE80211_RADIOTAP_MCS_HAVE_BW) {
            ss<<"HAVE_BW[";
            uint8_t bandwidth= flags & IEEE80211_RADIOTAP_MCS_BW_MASK;
            switch (bandwidth) {
                case IEEE80211_RADIOTAP_MCS_BW_20:ss<<"BW_20";break;
                case IEEE80211_RADIOTAP_MCS_BW_40:ss<<"BW_40";break;
                case IEEE80211_RADIOTAP_MCS_BW_20L:ss<<"BW_20L";break;
                case IEEE80211_RADIOTAP_MCS_BW_20U:ss<<"BW_20U";break;
                default:ss<<"Unknown";
            }
            ss<<"],";
        }
        if(flags & IEEE80211_RADIOTAP_MCS_HAVE_MCS) {
            ss<<"HAVE_MCS,";
        }
        if(flags & IEEE80211_RADIOTAP_MCS_HAVE_GI) {
            ss<<"HAVE_GI,";
        }
        if(flags & IEEE80211_RADIOTAP_MCS_HAVE_FMT) {
            ss<<"HAVE_FMT,";
        }
        if(flags & IEEE80211_RADIOTAP_MCS_HAVE_FEC) {
            ss<<"HAVE_FEC,";
        }
        if(flags & IEEE80211_RADIOTAP_MCS_HAVE_STBC ) {
            ss<<"HAVE_STBC[";
            uint8_t stbc=flags & IEEE80211_RADIOTAP_MCS_STBC_MASK;
            switch (stbc) {
                case IEEE80211_RADIOTAP_MCS_STBC_1:ss<<"STBC_1";break;
                case IEEE80211_RADIOTAP_MCS_STBC_2:ss<<"STBC_2";break;
                case IEEE80211_RADIOTAP_MCS_STBC_3:ss<<"STBC_3";break;
                case IEEE80211_RADIOTAP_MCS_STBC_SHIFT:ss<<"STBC_SHIFT";break;
                default:ss<<"Unknown";
            }
            ss<<"],";
        }
        ss<<"]";
        return ss.str();
    }
    std::string flagsIEEE80211_RADIOTAP_CHANNEL(const uint8_t flags){
        std::stringstream ss;
        ss<<"All IEEE80211_RADIOTAP_CHANNEL values: [";
        if(flags &  IEEE80211_CHAN_CCK) {
            ss<<"CHAN_CCK,";
        }
        if(flags &  IEEE80211_CHAN_OFDM) {
            ss<<"CHAN_OFDM,";
        }
        if(flags &  IEEE80211_CHAN_2GHZ) {
            ss<<"CHAN_2GHZ,";
        }
        if(flags &  IEEE80211_CHAN_5GHZ) {
            ss<<"CHAN_5GHZ,";
        }
        if(flags &  IEEE80211_CHAN_DYN) {
            ss<<"CHAN_DYN,";
        }
        if(flags &  IEEE80211_CHAN_HALF) {
            ss<<"CHAN_HALF,";
        }
        if(flags &  IEEE80211_CHAN_QUARTER) {
            ss<<"CHAN_QUARTER,";
        }
        ss<<"]";
        return ss.str();
    }

    std::string flagsIEEE80211_RADIOTAP_RX_FLAGS(const uint8_t flags){
        std::stringstream ss;
        ss<<"All IEEE80211_RADIOTAP_RX_FLAGS values: [";
        if(flags &  IEEE80211_RADIOTAP_F_RX_BADPLCP) {
            ss<<"RX_BADPLCP,";
        }
        ss<<"]";
        return ss.str();
    }
    std::string flagsIEEE80211_RADIOTAP_TX_FLAGS(const uint8_t flags){
        std::stringstream ss;
        ss<<"All IEEE80211_RADIOTAP_TX_FLAGS: [";
        if(flags &  IEEE80211_RADIOTAP_F_TX_FAIL) {
            ss<<"TX_FAIL,";
        }
        if(flags &  IEEE80211_RADIOTAP_F_TX_CTS) {
            ss<<"TX_CTS,";
        }
        if(flags &  IEEE80211_RADIOTAP_F_TX_RTS) {
            ss<<"TX_RTS,";
        }
        if(flags &  IEEE80211_RADIOTAP_F_TX_NOACK) {
            ss<<"TX_NOACK,";
        }
        ss<<"]";
        return ss.str();
    }

    static void debugRadiotapHeader(const uint8_t *pkt,int pktlen){
        struct ieee80211_radiotap_iterator iterator{};
        int ret = ieee80211_radiotap_iterator_init(&iterator, (ieee80211_radiotap_header *) pkt, pktlen, NULL);
        if (ret) {
            std::cout<<"malformed radiotap header (init returns %d)"<<ret;
            return;
        }
        std::cout<<"Debuging Radiotap Header \n";
        while (ret == 0 ) {
            ret = ieee80211_radiotap_iterator_next(&iterator);
            if(iterator.is_radiotap_ns){
                //std::cout<<"Is in namespace\n";
            }
            if (ret){
                continue;
            }
            /* see if this argument is something we can use */
            switch (iterator.this_arg_index) {
                case IEEE80211_RADIOTAP_TSFT:
                    std::cout<<"IEEE80211_RADIOTAP_TSFT\n";
                    break;
                case IEEE80211_RADIOTAP_FLAGS:
                    //std::cout<<"IEEE80211_RADIOTAP_FLAGS\n";
                    std::cout<<flagsIEEE80211_RADIOTAP_FLAGS(*iterator.this_arg)<<"\n";
                    break;
                case IEEE80211_RADIOTAP_RATE:
                    std::cout<<"IEEE80211_RADIOTAP_RATE:"<<(int)(*iterator.this_arg)<<"\n";
                    break;
                case IEEE80211_RADIOTAP_DBM_ANTSIGNAL:
                    std::cout<<"IEEE80211_RADIOTAP_DBM_ANTSIGNAL:"<<(int)(*iterator.this_arg)<<"\n";
                    break;
                case IEEE80211_RADIOTAP_ANTENNA:
                    std::cout<<"IEEE80211_RADIOTAP_ANTENNA:"<<(int)(*iterator.this_arg)<<"\n";
                    break;
                case IEEE80211_RADIOTAP_CHANNEL:
                    //std::cout<<"IEEE80211_RADIOTAP_CHANNEL\n";
                    std::cout<<flagsIEEE80211_RADIOTAP_CHANNEL(*iterator.this_arg)<<" \n";
                    break;
                case IEEE80211_RADIOTAP_MCS:
                    //std::cout<<"IEEE80211_RADIOTAP_MCS\n";
                    std::cout<<flagsIEEE80211_RADIOTAP_MCS(*iterator.this_arg)<<"\n";
                    break;
                case IEEE80211_RADIOTAP_RX_FLAGS:
                    //std::cout<<"IEEE80211_RADIOTAP_RX_FLAGS\n";
                    std::cout<< flagsIEEE80211_RADIOTAP_RX_FLAGS(*iterator.this_arg)<<"\n";
                    break;
                case IEEE80211_RADIOTAP_TX_FLAGS:
                    //std::cout<<"IEEE80211_RADIOTAP_TX_FLAGS\n";
                    std::cout<<flagsIEEE80211_RADIOTAP_TX_FLAGS(*iterator.this_arg)<<"\n";
                    break;
                case IEEE80211_RADIOTAP_AMPDU_STATUS:
                    std::cout<<"EEE80211_RADIOTAP_AMPDU_STATUS\n";
                    break;
                case IEEE80211_RADIOTAP_VHT:
                    std::cout<<"IEEE80211_RADIOTAP_VHT\n";
                    break;
                case IEEE80211_RADIOTAP_TIMESTAMP:
                    std::cout<<"IEEE80211_RADIOTAP_TIMESTAMP\n";
                    break;
                case IEEE80211_RADIOTAP_LOCK_QUALITY:
                    std::cout<<"IEEE80211_RADIOTAP_LOCK_QUALITY\n";
                    break;
                default:
                    std::cout<<"Unknown radiotap argument:"<<(int)iterator.this_arg_index<<"\n";
                    break;
            }
        }  /* while more rt headers */
    }
}

// what people used for whatever reason once on OpenHD / EZ-Wifibroadcast
namespace OldRadiotapHeaders{
    // https://github.com/OpenHD/Open.HD/blob/2.0/wifibroadcast-base/tx_telemetry.c#L123
    static uint8_t u8aRadiotapHeader[] = {
            0x00, 0x00,             // <-- radiotap version
            0x0c, 0x00,             // <- radiotap header length
            0x04, 0x80, 0x00, 0x00, // <-- radiotap present flags
            0x00,                   // datarate (will be overwritten later)
            0x00,
            0x00, 0x00
    };
    static uint8_t u8aRadiotapHeader80211n[] = {
            0x00, 0x00,             // <-- radiotap version
            0x0d, 0x00,             // <- radiotap header length
            0x00, 0x80, 0x08, 0x00, // <-- radiotap present flags (tx flags, mcs)
            0x08, 0x00,             // tx-flag
            0x37,                   // mcs have: bw, gi, stbc ,fec
            0x30,                   // mcs: 20MHz bw, long guard interval, stbc, ldpc
            0x00,                   // mcs index 0 (speed level, will be overwritten later)
    };

// this is what's used in
//https://github.com/OpenHD/Open.HD/blob/master/wifibroadcast-rc-Ath9k/rctx.cpp
    std::array<uint8_t,RadiotapHeader::SIZE_BYTES> radiotap_rc_ath9k={
            0, // <-- radiotap version      (0x00)
            0, // <-- radiotap version      (0x00)

            13, // <- radiotap header length (0x0d)
            0, // <- radiotap header length (0x00)

            0, // <-- radiotap present flags(0x00)
            128, // <-- RADIOTAP_TX_FLAGS +   (0x80)
            8, // <-- RADIOTAP_MCS          (0x08)
            0, //                           (0x00)

            8, // <-- RADIOTAP_F_TX_NOACK   (0x08)
            0, //                           (0x00)
            55, // <-- bitmap                (0x37)
            48, // <-- flags                 (0x30)
            0, // <-- mcs_index             (0x00)
    };
}



#endif //__WIFIBROADCAST_RADIOTAP_HEADER_HPP__