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

class FECEncoder{
public:
    explicit FECEncoder(int k, int n):fec_k(k),fec_n(n){
        fec_p = fec_new(fec_k, fec_n);

        block = new uint8_t *[fec_n];
        for (int i = 0; i < fec_n; i++) {
            block[i] = new uint8_t[MAX_FEC_PAYLOAD];
        }
    }
    ~FECEncoder(){
        for (int i = 0; i < fec_n; i++) {
            delete block[i];
        }
        delete block;

        fec_free(fec_p);
    }
    fec_t* fec_p;
    const int fec_k;  // RS number of primary fragments in block
    const int fec_n;  // RS total number of fragments in block
    uint64_t block_idx=0; //block_idx << 8 + fragment_idx = nonce (64bit)
    uint8_t fragment_idx=0;
    uint8_t** block;
    size_t max_packet_size=0;
public:
    /*void encode(const uint8_t *buf, size_t size){
        wpacket_hdr_t packet_hdr;
        assert(size <= MAX_PAYLOAD_SIZE);

        packet_hdr.packet_size = htobe16(size);
        memset(block[fragment_idx], '\0', MAX_FEC_PAYLOAD);
        memcpy(block[fragment_idx], &packet_hdr, sizeof(packet_hdr));
        memcpy(block[fragment_idx] + sizeof(packet_hdr), buf, size);
        send_block_fragment(sizeof(packet_hdr) + size);
        max_packet_size = std::max(max_packet_size, sizeof(packet_hdr) + size);
        fragment_idx += 1;

        if (fragment_idx < fec_k) return;

        fec_encode(fec_p, (const uint8_t **) block, block + fec_k, max_packet_size);
        while (fragment_idx < fec_n) {
            //send_block_fragment(max_packet_size);
            fragment_idx += 1;
        }
        block_idx += 1;
        fragment_idx = 0;
        max_packet_size = 0;
    }*/
};
#endif //WIFIBROADCAST_FEC_HPP
