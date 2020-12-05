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


#ifndef __WIFIBROADCAST_HPP__
#define __WIFIBROADCAST_HPP__

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
#include "Ieee80211Header.hpp"
#include "RadiotapHeader.hpp"

// The pcap packets sent out are never bigger than this size
static constexpr const auto MAX_PACKET_SIZE=1510;
static constexpr const auto MAX_RX_INTERFACES=8;



/*
 Wifibroadcast protocol:

 radiotap_header
   ieee_80211_header
     wblock_hdr_t   { packet_type, nonce = (block_idx << 8 + fragment_idx) }
       wpacket_hdr_t  { packet_size }  #
         data                          #
                                       +-- encrypted

 */

// nonce:  56bit block_idx + 8bit fragment_idx

#define BLOCK_IDX_MASK ((1LLU << 56) - 1)
#define MAX_BLOCK_IDX ((1LLU << 55) - 1)

static constexpr const uint8_t WFB_PACKET_DATA=0x1;
static constexpr const uint8_t WFB_PACKET_KEY=0x2;

static constexpr const auto SESSION_KEY_ANNOUNCE_DELTA=std::chrono::seconds(100);
static constexpr const auto RX_ANT_MAX=4;

// Header for forwarding raw packets from RX host to Aggregator in UDP packets
typedef struct {
    uint8_t wlan_idx;
    uint8_t antenna[RX_ANT_MAX]; //RADIOTAP_ANTENNA, list of antenna idx, 0xff for unused slot
    int8_t rssi[RX_ANT_MAX]; //RADIOTAP_DBM_ANTSIGNAL, list of rssi for corresponding antenna idx
} __attribute__ ((packed)) wrxfwd_t;

// Network packet headers. All numbers are in network (big endian) format
// Encrypted packets can be either session key or data packet.

// Session key packet

typedef struct {
    uint8_t packet_type;
    uint8_t session_key_nonce[crypto_box_NONCEBYTES];  // random data
    uint8_t session_key_data[crypto_aead_chacha20poly1305_KEYBYTES + crypto_box_MACBYTES]; // encrypted session key
} __attribute__ ((packed)) wsession_key_t;

// Data packet. Embed FEC-encoded data

typedef struct {
    uint8_t packet_type;
    uint64_t nonce;  // big endian, nonce = block_idx << 8 + fragment_idx
}  __attribute__ ((packed)) wblock_hdr_t;


// this header is written before the data of each FEC data packet
class FECDataHeader {
private:
    // private member to make sure it has always the right endian
    uint16_t packet_size; // big endian
public:
    explicit FECDataHeader(std::size_t packetSize1){
        // convert to big endian if needed
        packet_size=htobe16(packetSize1);
    }
    // convert from big endian if needed
    std::size_t get()const{
        return be16toh(packet_size);
    }
}  __attribute__ ((packed));
static_assert(sizeof(FECDataHeader) == 2, "ALWAYS_TRUE");

template<typename IS_DATA_PACKET>
class FECPacket{
public:
    uint8_t* data;
    std::size_t dataSize;
};

class XBlock{
public:
    wblock_hdr_t header;
    // If this is an FEC data packet, first two bytes of payload are the FECDataHeader
    // If this is an FEC correction packet, that's not the case
    uint8_t* payload;
    std::size_t payloadSize;
}__attribute__ ((packed));


static constexpr const auto MAX_PAYLOAD_SIZE=(MAX_PACKET_SIZE - RadiotapHeader::SIZE_BYTES - Ieee80211Header::SIZE_BYTES - sizeof(wblock_hdr_t) - crypto_aead_chacha20poly1305_ABYTES - sizeof(FECDataHeader));
static constexpr const auto MAX_FEC_PAYLOAD=(MAX_PACKET_SIZE - RadiotapHeader::SIZE_BYTES - Ieee80211Header::SIZE_BYTES - sizeof(wblock_hdr_t) - crypto_aead_chacha20poly1305_ABYTES);
static constexpr const auto MAX_FORWARDER_PACKET_SIZE=(MAX_PACKET_SIZE - RadiotapHeader::SIZE_BYTES - Ieee80211Header::SIZE_BYTES);


#endif //__WIFIBROADCAST_HPP__
