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

/**
 * Wifibroadcast protocol:
 * radiotap_header
 * * ieee_80211_header
 * ** if WFB_PACKET_KEY
 * *** WBSessionKeyPacket
 * ** if WFB_PACKET_DATA
 * *** wblock_hdr_t
 * **** encrypted payload data (dynamic size)
 */


// nonce:  56bit block_idx + 8bit fragment_idx
#define BLOCK_IDX_MASK ((1LLU << 56) - 1)
#define MAX_BLOCK_IDX ((1LLU << 55) - 1)

static constexpr const uint8_t WFB_PACKET_DATA=0x1;
static constexpr const uint8_t WFB_PACKET_KEY=0x2;
// for testing, do not use in production (just don't send it on the tx)
static constexpr const uint8_t WFB_PACKET_LATENCY_BEACON=0x3;

// the encryption key is sent every n seconds ( but not re-created every n seconds, it is only re-created when reaching the max sequence number
static constexpr const auto SESSION_KEY_ANNOUNCE_DELTA=std::chrono::seconds(5);


// Network packet headers. All numbers are in network (big endian) format
// Encrypted packets can be either session key or data packet.

// Session key packet
// Since the size of each session key packet never changes, this memory layout is the easiest
class WBSessionKeyPacket{
public:
    // note how this member doesn't add up to the size of this class (c++ is so great !)
    static constexpr auto SIZE_BYTES=(sizeof(uint8_t)+crypto_box_NONCEBYTES+crypto_aead_chacha20poly1305_KEYBYTES + crypto_box_MACBYTES);
public:
    const uint8_t packet_type=WFB_PACKET_KEY;
    uint8_t session_key_nonce[crypto_box_NONCEBYTES];  // random data
    uint8_t session_key_data[crypto_aead_chacha20poly1305_KEYBYTES + crypto_box_MACBYTES]; // encrypted session key
}__attribute__ ((packed));
static_assert(sizeof(WBSessionKeyPacket) == WBSessionKeyPacket::SIZE_BYTES, "ALWAYS_TRUE");


// This header comes with each FEC packet (data or fec correction packet)
struct wblock_hdr_t{
    const uint8_t packet_type=WFB_PACKET_DATA;
    uint64_t nonce;  // big endian, nonce = block_idx << 8 + fragment_idx
}  __attribute__ ((packed));


// this header is written before the data of each FEC data packet
// ONLY for data packets though ! (up to n bytes workaround)
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

class XBlock{
public:
    wblock_hdr_t header;
    // If this is an FEC data packet, first two bytes of payload are the FECDataHeader
    // If this is an FEC correction packet, that's not the case
    uint8_t* payload;
    std::size_t payloadSize;
}__attribute__ ((packed));

struct LatencyTestingPacket{
    uint8_t packet_type=WFB_PACKET_LATENCY_BEACON;
    std::chrono::steady_clock::time_point timestamp=std::chrono::steady_clock::now();
}__attribute__ ((packed));

// The pcap packets sent out are never bigger than this size
static constexpr const auto MAX_PACKET_SIZE=1510;
static constexpr const auto MAX_RX_INTERFACES=8;

static constexpr const auto MAX_PAYLOAD_SIZE=(MAX_PACKET_SIZE - RadiotapHeader::SIZE_BYTES - Ieee80211Header::SIZE_BYTES - sizeof(wblock_hdr_t) - crypto_aead_chacha20poly1305_ABYTES - sizeof(FECDataHeader));
static constexpr const auto MAX_FEC_PAYLOAD=(MAX_PACKET_SIZE - RadiotapHeader::SIZE_BYTES - Ieee80211Header::SIZE_BYTES - sizeof(wblock_hdr_t) - crypto_aead_chacha20poly1305_ABYTES);
static constexpr const auto MAX_FORWARDER_PACKET_SIZE=(MAX_PACKET_SIZE - RadiotapHeader::SIZE_BYTES - Ieee80211Header::SIZE_BYTES);


#endif //__WIFIBROADCAST_HPP__
