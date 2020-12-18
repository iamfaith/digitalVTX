//
// Created by consti10 on 02.12.20.
//

#ifndef WIFIBROADCAST_FEC_HPP
#define WIFIBROADCAST_FEC_HPP

#include "wifibroadcast.hpp"
extern "C"{
#include "ExternalCSources/fec.h"
}
#include "HelperSources/TimeHelper.hpp"
#include <cstdint>
#include <cerrno>
#include <string>
#include <vector>
#include <cstring>
#include <stdexcept>
#include <iostream>
#include <functional>
#include <map>
#include <queue>
#include <deque>

// c++ wrapper for the FEC library
// If K and N were known at compile time we could make this much cleaner !
class FEC{
public:
    explicit FEC(int k, int n) : FEC_K(k), FEC_N(n){
        if(FEC_K != 0){
            fec_p = fec_new(FEC_K, FEC_N);
        }
    }
    ~FEC(){
        if(fec_p!= nullptr){
            fec_free(fec_p);
        }
    }
    void fecEncode(const uint8_t** src,uint8_t ** fecs, size_t sz)const{
        fec_encode(fec_p,src,fecs,sz);
    }
    void fecDecode(const uint8_t** inpkts, uint8_t** outpkts, const unsigned*  index, size_t sz)const{
        fec_decode(fec_p,inpkts,outpkts,index,sz);
    }
public:
    const int FEC_K;  // RS number of primary fragments in block default 8
    const int FEC_N;  // RS total number of fragments in block default 12
private:
    fec_t *fec_p=nullptr;
};

// Takes a continuous stream of packets and
// encodes them via FEC such that they can be decoded by FECDecoder
// The encoding is slightly different from traditional FEC. It
// a) makes sure to send out data packets immediately
// b) Handles packets of size up to N instead of packets of exact size N
// Due to b) the packet size has to be written into the first two bytes of each data packet. See https://github.com/svpcom/wifibroadcast/issues/67
// use FEC_K==0 to completely skip FEC for the lowest latency possible
class FECEncoder : private FEC{
public:
    typedef std::function<void(const WBDataPacket &wbDataPacket)> OUTPUT_DATA_CALLBACK;
    OUTPUT_DATA_CALLBACK outputDataCallback;

    explicit FECEncoder(int k, int n) : FEC(k,n) {
        block = new uint8_t *[FEC_N];
        for (int i = 0; i < FEC_N; i++) {
            block[i] = new uint8_t[MAX_FEC_PAYLOAD];
        }
    }

    ~FECEncoder() {
        for (int i = 0; i < FEC_N; i++) {
            delete block[i];
        }
        delete block;
    }
private:
    uint64_t block_idx = 0; //block_idx << 8 + fragment_idx = nonce (64bit)
    uint8_t fragment_idx = 0;
    uint8_t **block;
    size_t max_packet_size = 0;
    //
public:
    void encodePacket(const uint8_t *buf,const size_t size) {
        assert(size <= MAX_PAYLOAD_SIZE);
        // Use FEC_K==0 to completely disable FEC
        if(FEC_K == 0) {
            const auto nonce=WBDataHeader::calculateNonce(block_idx,fragment_idx);
            WBDataPacket wbDataPacket{nonce, buf, size};
            outputDataCallback(wbDataPacket);
            block_idx++;
            return;
        }
        FECDataHeader dataHeader(size);
        // write the size of the data part into each primary fragment.
        // This is needed for the 'up to n bytes' workaround
        memcpy(block[fragment_idx], &dataHeader, sizeof(dataHeader));
        // write the actual data
        memcpy(block[fragment_idx] + sizeof(dataHeader), buf, size);
        // zero out the remaining bytes such that FEC always sees zeroes
        // same is done on the rx. These zero bytes are never transmitted via wifi
        const auto writtenDataSize= sizeof(FECDataHeader) + size;
        memset(block[fragment_idx]+writtenDataSize, '\0', MAX_FEC_PAYLOAD-writtenDataSize);

        // send primary fragments immediately before calculating the FECs
        send_block_fragment(sizeof(dataHeader) + size);
        // the packet size for FEC encoding is determined by calculating the max of all primary fragments in this block.
        // Since the rest of the bytes are zeroed out we can run FEC with dynamic packet size.
        // As long as the deviation in packet size of primary fragments isn't too high the loss in raw bandwidth is negligible
        // Note,the loss in raw bandwidth comes from the size of the FEC secondary packets, which always has to be the max of all primary fragments
        // Not from the primary fragments, they are transmitted without the "zeroed out" part
        max_packet_size = std::max(max_packet_size, sizeof(dataHeader) + size);
        fragment_idx += 1;

        //std::cout<<"Fragment index is "<<(int)fragment_idx<<"FEC_K"<<(int)FEC_K<<"\n";
        if (fragment_idx < FEC_K) {
            return;
        }
        // once enough data has been buffered, create all the secondary fragments
        fecEncode((const uint8_t **) block, block + FEC_K, max_packet_size);
        // and send all the secondary fragments one after another
        while (fragment_idx < FEC_N) {
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
        if (block_idx > WBDataHeader::MAX_BLOCK_IDX) {
            block_idx = 0;
            fragment_idx=0;
            return true;
        }
        return false;
    }
private:
    // construct WB data packet, from either primary or secondary fragment
    // then forward via the callback
    void send_block_fragment(const std::size_t packet_size) const {
        const auto nonce=WBDataHeader::calculateNonce(block_idx,fragment_idx);
        const uint8_t *dataP = block[fragment_idx];
        WBDataPacket packet{nonce, dataP, packet_size};
        outputDataCallback(packet);
    }
};

// This encapsulates everything you need when working on a single FEC block
// for example, addFragment() or forwardPrimaryFragment()
// it also keeps track of how many primary fragments have already been forwarded.
// and allows you to do the FEC step once enough secondary fragments have been received
class RxBlock{
public:
    explicit RxBlock(const FEC& fec, const uint64_t block_idx=0): fec(fec), fragment_map(fec.FEC_N, FragmentStatus::UNAVAILABLE), fragments(fec.FEC_N), originalSizeOfFragments(fec.FEC_N){
        repurpose(block_idx);
    }
    ~RxBlock()= default;
public:
    // Use this once the decoder is done with this item and uses it for a different block
    void repurpose(const uint64_t new_block_idx= 0){
        block_idx = new_block_idx;
        nAlreadyForwardedPrimaryFragments = 0;
        nAvailablePrimaryFragments=0;
        nAvailableSecondaryFragments=0;
        // mark every fragment as not yet received
        std::fill(fragment_map.begin(),fragment_map.end(),FragmentStatus::UNAVAILABLE);
    }
    // returns true if the fragment at position fragmentIdx has been already received
    bool hasFragment(const uint8_t fragmentIdx)const{
        return fragment_map[fragmentIdx]==AVAILABLE;
    }
    // returns true if we are "done with this block" aka all data has been already forwarded
    bool allPrimaryFragmentsHaveBeenForwarded()const{
        // never send out secondary fragments !
        assert(nAlreadyForwardedPrimaryFragments <= fec.FEC_K);
        return nAlreadyForwardedPrimaryFragments == fec.FEC_K;
    }
    // returns true if enough FEC secondary fragments are available to replace all missing primary fragments
    bool allPrimaryFragmentsCanBeRecovered()const{
        if(nAvailablePrimaryFragments+nAvailableSecondaryFragments>=fec.FEC_K)return true;
        return false;
    }
    // returns true if suddenly all primary fragments have become available
    bool allPrimaryFragmentsAreAvailable()const{
        return nAvailablePrimaryFragments==fec.FEC_K;
    }
    // copy the fragment data and mark it as available
    // you should check if it is already available with hasFragment() to avoid storing a fragment multiple times
    // when using multiple RX cards
    void addFragment(const uint8_t fragment_idx, const uint8_t* data,const std::size_t dataLen){
        assert(fragment_map[fragment_idx]==UNAVAILABLE);
        // write the data (doesn't matter if FEC data or correction packet)
        memcpy(fragments[fragment_idx].data(),data,dataLen);
        // set the rest to zero such that FEC works
        memset(fragments[fragment_idx].data()+dataLen, '\0', MAX_FEC_PAYLOAD-dataLen);
        // mark it as available
        fragment_map[fragment_idx] = RxBlock::AVAILABLE;
        // store the size of the received fragment for later use in the fec step
        originalSizeOfFragments[fragment_idx]=dataLen;
        if(fragment_idx<fec.FEC_K){
            nAvailablePrimaryFragments++;
        }else{
            nAvailableSecondaryFragments++;
        }
    }
    // increase the n of already forwarded fragments by one
    // return the data pointer for this fragment
    // NOTE: be carefully to not get out of sync here !
    const uint8_t* forwardPrimaryFragment(const uint8_t fragmentIdx){
        assert(fragmentIdx<fec.FEC_K);
        //assert(fragmentIdx>=nAlreadyForwardedPrimaryFragments);
        nAlreadyForwardedPrimaryFragments++;
        return fragments[fragmentIdx].data();
    }
    int getNAlreadyForwardedPrimaryFragments()const{
        return nAlreadyForwardedPrimaryFragments;
    }
    int getNAvailableFragments()const{
        return nAvailablePrimaryFragments+nAvailableSecondaryFragments;
    }
    // make sure to check if enough secondary fragments are available before calling this method !
    // reconstructing only part of the missing data is not supported !
    // return: the n of reconstructed packets
    int reconstructAllMissingData(){
        std::cout<<"reconstructAllMissingData"<<nAvailablePrimaryFragments<<" "<<nAvailableSecondaryFragments<<" "<<fec.FEC_K<<"\n";
        // NOTE: FEC does only work if nPrimaryFragments+nSecondaryFragments>=FEC_K
        assert(nAvailablePrimaryFragments+nAvailableSecondaryFragments>=fec.FEC_K);
        unsigned index[fec.FEC_K];
        uint8_t const* in_blocks[fec.FEC_K];
        uint8_t *out_blocks[fec.FEC_N - fec.FEC_K];
        int j = fec.FEC_K;
        int ob_idx = 0;
        std::size_t tmpMaxPacketSize=0;
        for (int k = 0; k < fec.FEC_K; k++) {
            if (fragment_map[k]==AVAILABLE) {
                in_blocks[k] = fragments[k].data();
                index[k] = k;
            } else {
                for (; j < fec.FEC_N; j++) {
                    if (fragment_map[j]) {
                        tmpMaxPacketSize=originalSizeOfFragments[j];
                        in_blocks[k] = fragments[j].data();
                        out_blocks[ob_idx++] = fragments[k].data();
                        index[k] = j;
                        // mark recovered primary fragment as available
                        fragment_map[k]=AVAILABLE;
                        // mark used secondary packet as unavailable
                        fragment_map[j]=UNAVAILABLE;
                        j++;
                        break;
                    }else{
                        //std::cout<<"primary fragment "<<k<<" cannot be recovered yet\n";
                    }
                }
            }
        }
        assert(ob_idx>0);
        assert(tmpMaxPacketSize!=0);
        fec.fecDecode((const uint8_t **) in_blocks, out_blocks, index, tmpMaxPacketSize);
        return ob_idx;
    }
private:
    //reference to the FEC decoder (needed for k,n)
    const FEC& fec;
public:
    // the block idx marks which block this element currently refers to
    uint64_t block_idx=0;
private:
    // n of primary fragments that are already sent out
    int nAlreadyForwardedPrimaryFragments=0;
    // for each fragment (via fragment_idx) store if it has been received yet
    enum FragmentStatus{UNAVAILABLE=0,AVAILABLE=1};
    std::vector<FragmentStatus> fragment_map;
    // holds all the data for all received fragments (if fragment_map says UNAVALIABLE at this position, content is undefined)
    std::vector<std::array<uint8_t,MAX_FEC_PAYLOAD>> fragments;
    // holds the original size for all received fragments
    std::vector<std::size_t> originalSizeOfFragments;
    int nAvailablePrimaryFragments=0;
    int nAvailableSecondaryFragments=0;
};

// Takes a continuous stream of packets (data and fec correction packets) and
// processes them such that the output is exactly (or as close as possible) to the
// Input stream fed to FECEncoder.
// Most importantly, it also handles re-ordering of packets and packet duplicates due to multiple rx cards
class FECDecoder : public FEC{
public:
    static constexpr auto RX_RING_SIZE = 40;
    typedef std::function<void(const uint8_t * payload,std::size_t payloadSize)> SEND_DECODED_PACKET;
    SEND_DECODED_PACKET callback;

    explicit FECDecoder(int k, int n) : FEC(k,n) {
        for(int i=0;i<RX_RING_SIZE;i++){
            rx_ring[i]=std::make_unique<RxBlock>(*this);
        }
    }
    ~FECDecoder() = default;
public:
    // call on new session key !
    void reset() {
        seq = 0;
        temporaryBlock= nullptr;
        // rx ring part
        rx_ring_front = 0;
        rx_ring_alloc = 0;
        last_known_block = (uint64_t) -1;
        for (int ring_idx = 0; ring_idx < FECDecoder::RX_RING_SIZE; ring_idx++) {
            rx_ring[ring_idx]->repurpose();
        }
    }
    // returns false if the packet is bad (which should never happen !)
    bool validateAndProcessPacket(const WBDataHeader& wblockHdr, const std::vector<uint8_t>& decrypted){
        assert(wblockHdr.packet_type==WFB_PACKET_DATA);
        // Use FEC_K==0 to completely disable FEC
        if(FEC_K == 0) {
            callback(decrypted.data(),decrypted.size());
            return true;
        }
        const uint64_t block_idx=wblockHdr.getBlockIdx();
        const uint8_t fragment_idx=wblockHdr.getFragmentIdx();

        // Should never happen due to generating new session key on tx side
        if (block_idx > WBDataHeader::MAX_BLOCK_IDX) {
            std::cerr<<"block_idx overflow\n";
            return false;
        }
        // fragment index must be in the range [0,...,FEC_N[
        if (fragment_idx >= FEC_N) {
            std::cerr<<"invalid fragment_idx:"<<fragment_idx<<"\n";
            return false;
        }
        //processFECBlockWithoutRxQueue(block_idx, fragment_idx, decrypted);
        processFECBlockWitRxQueue(block_idx,fragment_idx,decrypted);
        return true;
    }
private:
    uint64_t seq = 0;
    std::unique_ptr<RxBlock> temporaryBlock=nullptr;
    /**
     * forward as many primary fragments as they are available until there is a gap
     * starting at the primary fragment we stopped on last time
     * @param breakOnFirstGap : if true, stop on the first gap in all primary fragments. Else, keep going skipping packets with gaps
     */
    void forwardMissingPrimaryFragmentsIfAvailable(RxBlock& rxRingItem, const bool breakOnFirstGap= true){
        std::cout<<"forwardMissingPrimaryFragmentsIfAvailable\n";
        for(int i=rxRingItem.getNAlreadyForwardedPrimaryFragments(); i < FEC_K; i++){
            if(!rxRingItem.hasFragment(i)){
                if(breakOnFirstGap){
                    break;
                }else{
                    continue;
                }
            }
            forwardPrimaryFragment(rxRingItem, i);
        }
    }
    /**
     * Forward the primary (data) fragment at index fragmentIdx via the output callback
     */
    void forwardPrimaryFragment(RxBlock& rxRingItem, const uint8_t fragmentIdx){
        std::cout<<"forwardPrimaryFragment"<<fragmentIdx<<"\n";
        assert(fragmentIdx<FEC_K);
        assert(rxRingItem.hasFragment(fragmentIdx));
        const uint8_t* primaryFragment= rxRingItem.forwardPrimaryFragment(fragmentIdx);
        const FECDataHeader *packet_hdr = (FECDataHeader*) primaryFragment;

        const uint8_t *payload = primaryFragment + sizeof(FECDataHeader);
        const uint16_t packet_size = packet_hdr->get();
        const uint64_t packet_seq = rxRingItem.block_idx * FEC_K + fragmentIdx;

        if (packet_seq > seq + 1) {
            const auto packetsLost=(packet_seq - seq - 1);
            std::cerr<<packetsLost<<"packets lost\n";
            count_p_lost += packetsLost;
        }
        seq = packet_seq;
        if (packet_size > MAX_PAYLOAD_SIZE) {
            // this should never happen !
            std::cerr<<"corrupted packet on FECDecoder out "<<seq;
        } else {
            callback(payload,packet_size);
        }
    }
    void processFECBlockWithoutRxQueue(const uint64_t block_idx, const uint8_t fragment_idx, const std::vector<uint8_t>& decrypted){
        // allocate only on the first time, then use repurpose to avoid memory fragmentation
        if(temporaryBlock==nullptr){
            temporaryBlock=std::make_unique<RxBlock>(*this, block_idx);
        }
        if(temporaryBlock->block_idx!=block_idx){
            if(temporaryBlock->block_idx<block_idx) {
                // we move on to the next block. However, make sure to send stuff from before even though it has gaps in between
                forwardMissingPrimaryFragmentsIfAvailable(*temporaryBlock, false);
                temporaryBlock->repurpose(block_idx);
            }else{
                std::cout<<"We got block "<<block_idx<<" but already moved up to a higher one"<<temporaryBlock->block_idx<<"\n";
                return;
            }
        }
        // get rid of any duplicate information
        // if we are already done with this block, return early
        if(temporaryBlock->allPrimaryFragmentsHaveBeenForwarded()){
            return;
        }
        // we've already got this fragment for this block
        if(temporaryBlock->hasFragment(fragment_idx)){
            return;
        }
        // now add the new information
        temporaryBlock->addFragment(fragment_idx, decrypted.data(), decrypted.size());

        // forward primary fragments until there is a gap starting at the fragment we stopped on last time
        forwardMissingPrimaryFragmentsIfAvailable(*temporaryBlock);

        if(temporaryBlock->allPrimaryFragmentsHaveBeenForwarded()){
            //std::cout<<"Done with block "<<temporaryBlock->block_idx<<"\n";
            return;
        }
        if(temporaryBlock->allPrimaryFragmentsCanBeRecovered()){
            count_p_fec_recovered=temporaryBlock->reconstructAllMissingData();
            forwardMissingPrimaryFragmentsIfAvailable(*temporaryBlock);
            assert(temporaryBlock->allPrimaryFragmentsHaveBeenForwarded());
        }
    }
private:
    // Here is everything you need when using the RX queue to account for packet re-ordering due to multiple wifi cards
    std::array<std::unique_ptr<RxBlock>,RX_RING_SIZE> rx_ring;
    int rx_ring_front = 0; // current packet
    int rx_ring_alloc = 0; // number of allocated entries
    uint64_t last_known_block = ((uint64_t) -1);  //id of last known block
    //
    static inline int modN(int x, int base) {
        return (base + (x % base)) % base;
    }
    int rxRingPushFront() {
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
        std::cerr<<"override block "<<rx_ring[idx]->block_idx<<" with "<< rx_ring[idx]->getNAvailableFragments()<<" fragments\n";

        rx_ring_front = modN(rx_ring_front + 1, RX_RING_SIZE);
        return idx;
    }
    // TODO documentation
    // copy paste from svpcom
    int get_block_ring_idx(const uint64_t block_idx) {
        // check if block is already in the ring
        for (int i = rx_ring_front, c = rx_ring_alloc; c > 0; i = modN(i + 1, FECDecoder::RX_RING_SIZE), c--) {
            if (rx_ring[i]->block_idx == block_idx) return i;
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
            ring_idx = rxRingPushFront();
            const auto newBlockIdx=block_idx + i + 1 - new_blocks;
            rx_ring[ring_idx]->repurpose(newBlockIdx);
        }
        return ring_idx;
    }
    void rxRingPopFront(){
        rx_ring_front = modN(rx_ring_front + 1, RX_RING_SIZE);
        rx_ring_alloc -= 1;
        assert(rx_ring_alloc >= 0);
    }

    void processFECBlockWitRxQueue(const uint64_t block_idx, const uint8_t fragment_idx, const std::vector<uint8_t>& decrypted){
        const int ring_idx = get_block_ring_idx(block_idx);

        //printf("got 0x%lx %d, ring_idx=%d\n", block_idx, fragment_idx, ring_idx);

        //ignore already processed blocks
        if (ring_idx < 0) return;
        // cannot be nullptr
        RxBlock& block = *rx_ring[ring_idx].get();
        // ignore already processed fragments
        if(block.hasFragment(fragment_idx)){
            return;
        }
        block.addFragment(fragment_idx, decrypted.data(), decrypted.size());
        std::cout<<"Allocated entries "<<rx_ring_alloc<<"\n";

        if (ring_idx == rx_ring_front) {
            // forward packets until the first gap
            forwardMissingPrimaryFragmentsIfAvailable(block);
            // We are done with this block if either all fragments have been forwarded or it can be recovered
            if(block.allPrimaryFragmentsHaveBeenForwarded()){
                // remove block when done with it
                rxRingPopFront();
                return;
            }
            if(block.allPrimaryFragmentsCanBeRecovered()){
                count_p_fec_recovered=block.reconstructAllMissingData();
                forwardMissingPrimaryFragmentsIfAvailable(block);
                assert(block.allPrimaryFragmentsHaveBeenForwarded());
                // remove block when done with it
                rxRingPopFront();
                return;
            }
            return;
        }else{
            // we are not in the front of the queue but somewhere else
            // If this block can be fully recovered or all primary fragments are available this triggers a flush
            if(block.allPrimaryFragmentsAreAvailable() || block.allPrimaryFragmentsCanBeRecovered()){
                // send all queued packets in all unfinished blocks before and remove them
                int nrm = modN(ring_idx - rx_ring_front, RX_RING_SIZE);
                while(nrm > 0) {
                    forwardMissingPrimaryFragmentsIfAvailable(*rx_ring[rx_ring_front], false);
                    rxRingPopFront();
                    nrm -= 1;
                }
                // then process the block who is fully recoverable or has no gaps in the primary fragments
                if(block.allPrimaryFragmentsAreAvailable()){
                    forwardMissingPrimaryFragmentsIfAvailable(block);
                    assert(block.allPrimaryFragmentsHaveBeenForwarded());
                }else{
                    // apply fec for this block
                    count_p_fec_recovered=block.reconstructAllMissingData();
                    forwardMissingPrimaryFragmentsIfAvailable(block);
                    assert(block.allPrimaryFragmentsHaveBeenForwarded());
                }
                // remove block
                rxRingPopFront();
            }
        }
    }
protected:
    uint32_t count_p_fec_recovered=0;
    uint32_t count_p_lost=0;
    //
};


#endif //WIFIBROADCAST_FEC_HPP
