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

namespace RadiotapFlagsToString{
    std::string flagsIEEE80211_RADIOTAP_MCS(const uint8_t flags) {
        std::stringstream ss;
        ss<<"All IEEE80211_RADIOTAP_MCS flags: ";
        if(flags &  IEEE80211_RADIOTAP_MCS_HAVE_BW) {
            auto bw=flags & IEEE80211_RADIOTAP_MCS_BW_MASK;
            ss<<"HAVE_BW["<<(int)bw<<"],";
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
            ss<<"HAVE_STBC,";
        }
        return ss.str();
    }
    std::string flagsIEEE80211_RADIOTAP_FLAGS(uint8_t flags){
        std::stringstream ss;
        ss<<"All IEEE80211_RADIOTAP flags: ";
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
        return ss.str();
    }
}

// hmmmmmmmmmmmmmmm https://github.com/vanhoefm/modwifi-tools/blob/master/ieee80211header.h#L16
struct ieee80211_radiotap_ath9k_htc {
        uint8_t        it_version;     /* set to 0 */
        uint8_t        it_pad;
        uint16_t       it_len;         /* entire length */
        uint32_t       it_present;     /* fields present */
        uint64_t       tsf;
        uint8_t        flags;
        uint8_t        rate;
        uint16_t       frequency;
        uint16_t       channelflags;
        int8_t         dbsignal;
        uint8_t        antenna;
        uint16_t       rxflags;
        uint8_t        padding[8];
}__attribute__ ((packed));
static_assert(sizeof(ieee80211_radiotap_ath9k_htc)==34,"ALWAYS_TRUE");

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


// https://github.com/OpenHD/Open.HD/blob/2.0/wifibroadcast-base/tx_telemetry.c#L123
namespace LULATSCH{
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
}



#endif //__WIFIBROADCAST_RADIOTAP_HEADER_HPP__