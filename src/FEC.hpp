//
// Created by consti10 on 02.12.20.
//

#ifndef WIFIBROADCAST_FEC_HPP
#define WIFIBROADCAST_FEC_HPP
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <errno.h>
#include <string>
#include <vector>
#include <string.h>
#include "fec.h"
#include "wifibroadcast.hpp"
#include <stdexcept>
#include <iostream>
#include <functional>

/**
 * All this code was originally written in svpcom/wifibroadcast
 * Myself I don't understand everything, but it works pretty good
 */

class FECEncoder{
public:
    explicit FECEncoder(int k, int n):fec_k(k),fec_n(n){
        fec_p = fec_new(fec_k, fec_n);
        block = new uint8_t *[fec_n];
        for (int i = 0; i < fec_n; i++) {
            block[i] = new uint8_t[MAX_FEC_PAYLOAD];
        }
        /*block.resize(fec_n);
        for(int i=0;i<fec_n;i++){
            block[i].resize(MAX_FEC_PAYLOAD);
        }*/
    }
    ~FECEncoder(){
        for (int i = 0; i < fec_n; i++) {
            delete block[i];
        }
        delete block;
        fec_free(fec_p);
    }
private:
    fec_t* fec_p;
    const int fec_k;  // RS number of primary fragments in block default 8
    const int fec_n;  // RS total number of fragments in block default 12
    uint64_t block_idx=0; //block_idx << 8 + fragment_idx = nonce (64bit)
    uint8_t fragment_idx=0;
    uint8_t** block;
    //std::vector<std::vector<uint8_t>> block;
    size_t max_packet_size=0;
public:
    typedef std::function<void(const XBlock& xBlock)> SEND_BLOCK_FRAGMENT;
    SEND_BLOCK_FRAGMENT callback;
    void encodePacket(const uint8_t *buf, size_t size){
        assert(size <= MAX_PAYLOAD_SIZE);
        wpacket_hdr_t packet_hdr;

        packet_hdr.packet_size = htobe16(size);
        memset(block[fragment_idx], '\0', MAX_FEC_PAYLOAD);
        memcpy(block[fragment_idx], &packet_hdr, sizeof(packet_hdr));
        memcpy(block[fragment_idx] + sizeof(packet_hdr), buf, size);
        // send immediately before calculating the FECs
        send_block_fragment(sizeof(packet_hdr) + size);
        max_packet_size = std::max(max_packet_size, sizeof(packet_hdr) + size);
        fragment_idx += 1;

        //std::cout<<"Fragment index is "<<(int)fragment_idx<<"fec_k"<<(int)fec_k<<"\n";
        if (fragment_idx < fec_k){
            return;
        }
        // once enough data has been buffered, create and send all the FEC packets
        fec_encode(fec_p, (const uint8_t **) block, block + fec_k, max_packet_size);
        while (fragment_idx < fec_n) {
            send_block_fragment(max_packet_size);
            fragment_idx += 1;
        }
        block_idx += 1;
        fragment_idx = 0;
        max_packet_size = 0;
    }
    // returns true if the block_idx has reached its maximum
    // You want to send a new session key in this case
    bool resetOnOverflow(){
        if (block_idx > MAX_BLOCK_IDX) {
            block_idx = 0;
            return true;
        }
        return false;
    }
private:
    // construct WB FEC data, either DATA blocks or FEC blocks
    // then forward via the callback
    void send_block_fragment(const std::size_t packet_size)const{
        XBlock xBlock{};
        xBlock.header.packet_type = WFB_PACKET_DATA;
        xBlock.header.nonce=htobe64(((block_idx & BLOCK_IDX_MASK) << 8) + fragment_idx);
        uint8_t* dataP=block[fragment_idx];
        xBlock.payload=dataP;
        xBlock.payloadSize=packet_size;
        callback(xBlock);
    }
};

typedef struct {
    uint64_t block_idx;
    uint8_t** fragments;
    uint8_t *fragment_map;
    uint8_t send_fragment_idx;
    uint8_t has_fragments;
} rx_ring_item_t;

static inline int modN(int x, int base)
{
    return (base + (x % base)) % base;
}

class FECDecoder{
public:
static constexpr auto RX_RING_SIZE=40;
    explicit FECDecoder( int k, int n):fec_k(k),fec_n(n)
    {
        fec_p = fec_new(fec_k, fec_n);

        for (int ring_idx = 0; ring_idx < RX_RING_SIZE; ring_idx++) {
            rx_ring[ring_idx].block_idx = 0;
            rx_ring[ring_idx].send_fragment_idx = 0;
            rx_ring[ring_idx].has_fragments = 0;
            rx_ring[ring_idx].fragments = new uint8_t *[fec_n];
            for (int i = 0; i < fec_n; i++) {
                rx_ring[ring_idx].fragments[i] = new uint8_t[MAX_FEC_PAYLOAD];
            }
            rx_ring[ring_idx].fragment_map = new uint8_t[fec_n];
            memset(rx_ring[ring_idx].fragment_map, '\0', fec_n * sizeof(uint8_t));
        }
    }
    ~FECDecoder(){
        for (int ring_idx = 0; ring_idx < RX_RING_SIZE; ring_idx++) {
            delete rx_ring[ring_idx].fragment_map;
            for (int i = 0; i < fec_n; i++) {
                delete rx_ring[ring_idx].fragments[i];
            }
            delete rx_ring[ring_idx].fragments;
        }
    }
public:
    fec_t* fec_p;
    const int fec_k;  // RS number of primary fragments in block
    const int fec_n;  // RS total number of fragments in block
    uint32_t seq=0;
    rx_ring_item_t rx_ring[RX_RING_SIZE];
    int rx_ring_front=0; // current packet
    int rx_ring_alloc=0; // number of allocated entries
    uint64_t last_known_block=((uint64_t) -1);  //id of last known block
protected:
    int rx_ring_push(){
        if (rx_ring_alloc < RX_RING_SIZE) {
            int idx = modN(rx_ring_front + rx_ring_alloc, RX_RING_SIZE);
            rx_ring_alloc += 1;
            return idx;
        }

        // override existing data
        int idx = rx_ring_front;

        /*
          Ring overflow. This means that there are more unfinished blocks than ring size
          Possible solutions:
          1. Increase ring size. Do this if you have large variance of packet travel time throught WiFi card or network stack.
             Some cards can do this due to packet reordering inside, diffent chipset and/or firmware or your RX hosts have different CPU power.
          2. Reduce packet injection speed or try to unify RX hardware.
        */

        fprintf(stderr, "override block 0x%" PRIx64 " with %d fragments\n", rx_ring[idx].block_idx,
                rx_ring[idx].has_fragments);

        rx_ring_front = modN(rx_ring_front + 1, RX_RING_SIZE);
        return idx;
    }
    int get_block_ring_idx(uint64_t block_idx){
        // check if block is already to the ring
        for (int i = rx_ring_front, c = rx_ring_alloc; c > 0; i = modN(i + 1, FECDecoder::RX_RING_SIZE), c--) {
            if (rx_ring[i].block_idx == block_idx) return i;
        }

        // check if block is already known and not in the ring then it is already processed
        if (last_known_block != (uint64_t) -1 && block_idx <= last_known_block) {
            return -1;
        }

        int new_blocks = (int) std::min(last_known_block != (uint64_t) -1 ? block_idx - last_known_block : 1,
                                        (uint64_t) FECDecoder::RX_RING_SIZE);
        assert (new_blocks > 0);

        last_known_block = block_idx;
        int ring_idx = -1;

        for (int i = 0; i < new_blocks; i++) {
            ring_idx = rx_ring_push();
            rx_ring[ring_idx].block_idx = block_idx + i + 1 - new_blocks;
            rx_ring[ring_idx].send_fragment_idx = 0;
            rx_ring[ring_idx].has_fragments = 0;
            memset(rx_ring[ring_idx].fragment_map, '\0', fec_n * sizeof(uint8_t));
        }
        return ring_idx;
    }
    void apply_fec(int ring_idx){
        unsigned index[fec_k];
        uint8_t *in_blocks[fec_k];
        uint8_t *out_blocks[fec_n - fec_k];
        int j = fec_k;
        int ob_idx = 0;

        for (int i = 0; i < fec_k; i++) {
            if (rx_ring[ring_idx].fragment_map[i]) {
                in_blocks[i] = rx_ring[ring_idx].fragments[i];
                index[i] = i;
            } else {
                for (; j < fec_n; j++) {
                    if (rx_ring[ring_idx].fragment_map[j]) {
                        in_blocks[i] = rx_ring[ring_idx].fragments[j];
                        out_blocks[ob_idx++] = rx_ring[ring_idx].fragments[i];
                        index[i] = j;
                        j++;
                        break;
                    }
                }
            }
        }
        fec_decode(fec_p, (const uint8_t **) in_blocks, out_blocks, index, MAX_FEC_PAYLOAD);
    }
};

#endif //WIFIBROADCAST_FEC_HPP
