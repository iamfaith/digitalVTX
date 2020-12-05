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
#include "wifibroadcast.hpp"
#include <stdexcept>
#include <iostream>
#include <functional>

extern "C"{
#include "fec.h"
}

/**
 * All this code was originally written in svpcom/wifibroadcast
 * I extracted the 'FEC part' into here
 */

// Takes a continuous stream of packets and
// encodes them via FEC such that they can be decoded by FECDecoder
// The encoding is slightly different from traditional FEC. It
// a) makes sure to send out data packets immediately
// b) Handles packets of size up to N instead of packets of exact size N
// Due to b) the packet size has to be written into the first two bytes of each data packet. See https://github.com/svpcom/wifibroadcast/issues/67
class FECEncoder {
public:
    typedef std::function<void(const XBlock &xBlock)> SEND_BLOCK_FRAGMENT;
    SEND_BLOCK_FRAGMENT callback;

    explicit FECEncoder(int k, int n) : fec_k(k), fec_n(n) {
        fec_p = fec_new(fec_k, fec_n);
        block = new uint8_t *[fec_n];
        for (int i = 0; i < fec_n; i++) {
            block[i] = new uint8_t[MAX_FEC_PAYLOAD];
        }
    }

    ~FECEncoder() {
        for (int i = 0; i < fec_n; i++) {
            delete block[i];
        }
        delete block;
        fec_free(fec_p);
    }
private:
    const int fec_k;  // RS number of primary fragments in block default 8
    const int fec_n;  // RS total number of fragments in block default 12
    fec_t *fec_p;
    uint64_t block_idx = 0; //block_idx << 8 + fragment_idx = nonce (64bit)
    uint8_t fragment_idx = 0;
    uint8_t **block;
    size_t max_packet_size = 0;
public:
    void encodePacket(const uint8_t *buf, size_t size) {
        assert(size <= MAX_PAYLOAD_SIZE);
        FECDataHeader packet_hdr(size);
        // write the size of the data part into each packet.
        // This is needed for the 'up to n bytes' workaround
        memcpy(block[fragment_idx], &packet_hdr, sizeof(packet_hdr));
        // write the actual data
        memcpy(block[fragment_idx] + sizeof(packet_hdr), buf, size);
        // zero out the remaining bytes such that FEC always sees zeroes
        // same is done on the rx. These zero bytes are never transmitted via wifi
        const auto writtenDataSize= sizeof(FECDataHeader) + size;
        memset(block[fragment_idx]+writtenDataSize, '\0', MAX_FEC_PAYLOAD-writtenDataSize);

        // send immediately before calculating the FECs
        send_block_fragment(sizeof(packet_hdr) + size);
        max_packet_size = std::max(max_packet_size, sizeof(packet_hdr) + size);
        fragment_idx += 1;

        //std::cout<<"Fragment index is "<<(int)fragment_idx<<"fec_k"<<(int)fec_k<<"\n";
        if (fragment_idx < fec_k) {
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
    bool resetOnOverflow() {
        if (block_idx > MAX_BLOCK_IDX) {
            block_idx = 0;
            return true;
        }
        return false;
    }

private:
    // construct WB FEC data, either DATA blocks or FEC blocks
    // then forward via the callback
    void send_block_fragment(const std::size_t packet_size) const {
        XBlock xBlock{};
        xBlock.header.packet_type = WFB_PACKET_DATA;
        xBlock.header.nonce = htobe64(((block_idx & BLOCK_IDX_MASK) << 8) + fragment_idx);
        uint8_t *dataP = block[fragment_idx];
        //const auto tmp=(wpacket_hdr_t*)dataP;
        //assert(packet_size==tmp->packet_size);
        //std::cout<<(int)packet_size<<" "<<(int)tmp->get();

        xBlock.payload = dataP;
        xBlock.payloadSize = packet_size;
        callback(xBlock);
    }
};

typedef struct {
    uint64_t block_idx;
    uint8_t **fragments;
    uint8_t *fragment_map;
    uint8_t send_fragment_idx;
    uint8_t has_fragments;
} rx_ring_item_t;

static inline int modN(int x, int base) {
    return (base + (x % base)) % base;
}

// Takes a continuous stream of packets (data and fec packets) and
// processes them such that the output is exactly (or as close as possible) to the
// Input stream fed to FECEncoder.
// Most importantly, it also handles re-ordering of packets
class FECDecoder {
public:
    static constexpr auto RX_RING_SIZE = 40;
    typedef std::function<void(const uint8_t * payload,std::size_t payloadSize)> SEND_DECODED_PACKET;
    SEND_DECODED_PACKET callback;

    explicit FECDecoder(int k, int n) : fec_k(k), fec_n(n) {
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

    ~FECDecoder() {
        for (int ring_idx = 0; ring_idx < RX_RING_SIZE; ring_idx++) {
            delete rx_ring[ring_idx].fragment_map;
            for (int i = 0; i < fec_n; i++) {
                delete rx_ring[ring_idx].fragments[i];
            }
            delete rx_ring[ring_idx].fragments;
        }
    }
private:
    fec_t *fec_p;
    const int fec_k;  // RS number of primary fragments in block
    const int fec_n;  // RS total number of fragments in block
    uint32_t seq = 0;
    //rx_ring_item_t rx_ring[RX_RING_SIZE];
    std::array<rx_ring_item_t,RX_RING_SIZE> rx_ring;
    int rx_ring_front = 0; // current packet
    int rx_ring_alloc = 0; // number of allocated entries
    uint64_t last_known_block = ((uint64_t) -1);  //id of last known block
    // TODO documentation
    // copy paste from svpcom
    int rx_ring_push() {
        if (rx_ring_alloc < RX_RING_SIZE) {
            int idx = modN(rx_ring_front + rx_ring_alloc, RX_RING_SIZE);
            rx_ring_alloc += 1;
            return idx;
        }

        // override existing data
        const int idx = rx_ring_front;

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
    // TODO documentation
    // copy paste from svpcom
    int get_block_ring_idx(uint64_t block_idx) {
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
    // TODO documentation
    // copy paste from svpcom
    void apply_fec(int ring_idx) {
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
    // this one calls the callback with reconstructed data and payload in order
    void send_packet(int ring_idx, int fragment_idx){
        const FECDataHeader *packet_hdr = (FECDataHeader *) (rx_ring[ring_idx].fragments[fragment_idx]);

        const uint8_t *payload = (rx_ring[ring_idx].fragments[fragment_idx]) + sizeof(FECDataHeader);
        const uint16_t packet_size = packet_hdr->get();//be16toh(packet_hdr->packet_size);
        const uint32_t packet_seq = rx_ring[ring_idx].block_idx * fec_k + fragment_idx;

        if (packet_seq > seq + 1) {
            fprintf(stderr, "%u packets lost\n", packet_seq - seq - 1);
            count_p_lost += (packet_seq - seq - 1);
        }

        seq = packet_seq;

        if (packet_size > MAX_PAYLOAD_SIZE) {
            fprintf(stderr, "corrupted packet %u\n", seq);
            count_p_bad += 1;
        } else {
            //send(sockfd, payload, packet_size, MSG_DONTWAIT);
            callback(payload,packet_size);
        }
    }
public:
    // call on new session key ?!
    void reset() {
        rx_ring_front = 0;
        rx_ring_alloc = 0;
        last_known_block = (uint64_t) -1;
        seq = 0;
        for (int ring_idx = 0; ring_idx < FECDecoder::RX_RING_SIZE; ring_idx++) {
            rx_ring[ring_idx].block_idx = 0;
            rx_ring[ring_idx].send_fragment_idx = 0;
            rx_ring[ring_idx].has_fragments = 0;
            memset(rx_ring[ring_idx].fragment_map, '\0', fec_n * sizeof(uint8_t));
        }
    }
    void processPacket(const wblock_hdr_t& wblockHdr,const std::vector<uint8_t>& decrypted){
        assert(wblockHdr.packet_type==WFB_PACKET_DATA);
        const uint64_t block_idx = be64toh(wblockHdr.nonce) >> 8;
        const uint8_t fragment_idx = (uint8_t) (be64toh(wblockHdr.nonce) & 0xff);

        // Should never happen due to generating new session key on tx side
        if (block_idx > MAX_BLOCK_IDX) {
            fprintf(stderr, "block_idx overflow\n");
            count_p_bad += 1;
            return;
        }

        if (fragment_idx >= fec_n) {
            fprintf(stderr, "invalid fragment_idx: %d\n", fragment_idx);
            count_p_bad += 1;
            return;
        }

        const int ring_idx = get_block_ring_idx(block_idx);

        //printf("got 0x%lx %d, ring_idx=%d\n", block_idx, fragment_idx, ring_idx);

        //ignore already processed blocks
        if (ring_idx < 0) return;

        rx_ring_item_t *p = &rx_ring[ring_idx];

        //ignore already processed fragments
        if (p->fragment_map[fragment_idx]) return;


        // write the data where first two bytes are the actual packet size
        memcpy(p->fragments[fragment_idx], decrypted.data(), decrypted.size());
        // set the rest to zero such that FEC works
        memset(p->fragments[fragment_idx]+decrypted.size(), '\0', MAX_FEC_PAYLOAD-decrypted.size());

        p->fragment_map[fragment_idx] = 1;
        p->has_fragments += 1;

        if (ring_idx == rx_ring_front) {
            // check if any packets without gaps
            while (p->send_fragment_idx < fec_k && p->fragment_map[p->send_fragment_idx]) {
                send_packet(ring_idx, p->send_fragment_idx);
                p->send_fragment_idx += 1;
            }
        }

        // or we can reconstruct gaps via FEC
        if (p->send_fragment_idx < fec_k && p->has_fragments == fec_k) {
            //printf("do fec\n");
            apply_fec(ring_idx);
            while (p->send_fragment_idx < fec_k) {
                count_p_fec_recovered += 1;
                send_packet(ring_idx, p->send_fragment_idx);
                p->send_fragment_idx += 1;
            }
        }

        if (p->send_fragment_idx == fec_k) {
            int nrm = modN(ring_idx - rx_ring_front, FECDecoder::RX_RING_SIZE);
            for (int i = 0; i <= nrm; i++) {
                rx_ring_front = modN(rx_ring_front + 1, FECDecoder::RX_RING_SIZE);
                rx_ring_alloc -= 1;
            }
            assert(rx_ring_alloc >= 0);
        }
    }
protected:
    uint32_t count_p_fec_recovered=0;
    uint32_t count_p_lost=0;
    uint32_t count_p_bad=0;
};

namespace TestFEC{
    static void test(const int k,const int n,const std::vector<std::vector<uint8_t>>& testIn){
        std::cout<<"Test K N SIZE "<<k<<" "<<n<<" "<<testIn.size()<<"\n";
        FECEncoder encoder(k,n);
        FECDecoder decoder(k,n);
        std::vector<std::vector<uint8_t>> testOut;

        const auto cb1=[&decoder](const XBlock &xBlock)mutable {
            decoder.processPacket(xBlock.header,std::vector<uint8_t>(xBlock.payload,xBlock.payload+xBlock.payloadSize));
        };
        const auto cb2=[&testOut](const uint8_t * payload,std::size_t payloadSize)mutable{
            testOut.emplace_back(payload,payload+payloadSize);
        };
        encoder.callback=cb1;
        decoder.callback=cb2;

        for(std::size_t i=0;i<testIn.size();i++){
            const auto& in=testIn[i];
            encoder.encodePacket(in.data(),in.size());
            const auto& out=testOut[i];
            assert(GenericHelper::compareVectors(in,out)==true);
        }
    }
    // No packet loss
    // Fixed packet size
    static void test(const int k,const int n,const std::size_t N_PACKETS){
        std::vector<std::vector<uint8_t>> testIn;
        for(std::size_t i=0;i<N_PACKETS;i++){
            testIn.push_back(GenericHelper::createRandomDataBuffer(20));
        }
        test(k,n,testIn);
    }

    // No packet loss
    // Dynamic packet size (up to N bytes)
    static void test2(const int k,const int n,const std::size_t N_PACKETS){
        std::vector<std::vector<uint8_t>> testIn;
        for(std::size_t i=0;i<N_PACKETS;i++){
            const auto size=rand() % MAX_PAYLOAD_SIZE;
            testIn.push_back(GenericHelper::createRandomDataBuffer(size));
        }
        test(k,n,testIn);
    }

    // test if everything is right with stupid deterministic packet loss
    /*static void test2(const int k,const int n,const std::vector<std::vector<uint8_t>>& testIn){
        std::cout<<"Test K N SIZE "<<k<<" "<<n<<" "<<testIn.size()<<"\n";
        FECEncoder encoder(k,n);
        FECDecoder decoder(k,n);
        std::vector<std::vector<uint8_t>> testOut;

        const auto cb1=[&decoder](const XBlock &xBlock)mutable {
            decoder.processPacket(xBlock.header,std::vector<uint8_t>(xBlock.payload,xBlock.payload+xBlock.payloadSize));
        };
        const auto cb2=[&testOut](const uint8_t * payload,std::size_t payloadSize)mutable{
            testOut.emplace_back(payload,payload+payloadSize);
        };
        encoder.callback=cb1;
        decoder.callback=cb2;

        int dropIdx=0;

        for(int i=0;i<testIn.size();i++){
            const auto& in=testIn[i];
            dropIdx++;
            if(dropIdx % 4==0){

            }else{

            }
            encoder.encodePacket(in.data(),in.size());
            const auto& out=testOut[i];
            assert(compareVectors(in,out)==true);
        }
    }*/
}

#endif //WIFIBROADCAST_FEC_HPP
