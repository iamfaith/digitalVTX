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

extern "C"{
#include "ExternalSources/ieee80211_radiotap.h"
};

// Default is MCS#1 -- QPSK 1/2 40MHz SGI -- 30 Mbit/s
// MCS_FLAGS = (IEEE80211_RADIOTAP_MCS_BW_40 | IEEE80211_RADIOTAP_MCS_SGI | (IEEE80211_RADIOTAP_MCS_STBC_1 << IEEE80211_RADIOTAP_MCS_STBC_SHIFT))

#define MCS_KNOWN (IEEE80211_RADIOTAP_MCS_HAVE_MCS | IEEE80211_RADIOTAP_MCS_HAVE_BW | IEEE80211_RADIOTAP_MCS_HAVE_GI | IEEE80211_RADIOTAP_MCS_HAVE_STBC | IEEE80211_RADIOTAP_MCS_HAVE_FEC)

// Wrapper around the radiotap header (declared as raw array initially)
// Used for injecting packets with the right parameters
class RadiotapHeader{
public:
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
            MCS_KNOWN , 0x00, 0x00 // bitmap, flags, mcs_index
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
                fprintf(stderr, "Unsupported bandwidth: %d\n", params.bandwidth);
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
                fprintf(stderr, "Unsupported STBC type: %d\n",params.stbc);
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

#endif //__WIFIBROADCAST_RADIOTAP_HEADER_HPP__