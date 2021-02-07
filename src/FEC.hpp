//
// Created by consti10 on 02.12.20.
//

#ifndef WIFIBROADCAST_FEC_HPP
#define WIFIBROADCAST_FEC_HPP

#include "wifibroadcast.hpp"
#include "ExternalCSources/fec/fec.h"
#include "HelperSources/TimeHelper.hpp"
#include <cstdint>
#include <cerrno>
#include <string>
#include <utility>
#include <vector>
#include <cstring>
#include <stdexcept>
#include <iostream>
#include <functional>
#include <map>

// NOTE: When working with FEC, people seem to use the terms block, fragments and more in different context(s).
// I use (and highly recommend this to anyone else) the following notation:
// A primary fragment is a data packet
// A secondary fragment is a data correction (FEC) packet
// K primary and N-K secondary fragments together form a FEC block

// c++ wrapper for the FEC library
// If K and N were known at compile time we could make this much cleaner !
class FEC{
public:
    explicit FEC(int k, int n) : FEC_K(k), FEC_N(n){
        assert(n>=k);
    }
public:
    const int FEC_K;  // RS number of primary fragments in block default 8
    const int FEC_N;  // RS total number of fragments in block default 12
    const int N_PRIMARY_FRAGMENTS=FEC_K;
    const int N_SECONDARY_FRAGMENTS=FEC_N-FEC_K;
};

// Takes a continuous stream of packets and
// encodes them via FEC such that they can be decoded by FECDecoder
// The encoding is slightly different from traditional FEC. It
// a) makes sure to send out data packets immediately
// b) Handles packets of size up to N instead of packets of exact size N
// Due to b) the packet size has to be written into the first two bytes of each data packet. See https://github.com/svpcom/wifibroadcast/issues/67
// use FEC_K==0 to completely skip FEC for the lowest latency possible
class FECEncoder{
public:
    typedef std::function<void(const uint64_t nonce,const uint8_t* payload,const std::size_t payloadSize)> OUTPUT_DATA_CALLBACK;
    OUTPUT_DATA_CALLBACK outputDataCallback;
    // TODO: So we have to be carefully here:
    // 1) If k,n is given: fixed packet size
    // 2) If k,n is not given, but we do variable k,(n) -> what to do ?
    explicit FECEncoder(int k, int n) : fec(k,n){
        fec_init();
        fragments.resize(fec.FEC_N);
        for (int i = 0; i < fec.FEC_N; i++) {
            fragments[i] = new uint8_t[MAX_FEC_PAYLOAD];
        }
    }
    ~FECEncoder() {
        for (int i = 0; i < fec.FEC_N; i++) {
            delete fragments[i];
        }
    }
    // K, N is fixed on the encoder side
    const FEC fec;
private:
    uint64_t currBlockIdx = 0; //block_idx << 8 + fragment_idx = nonce (64bit)
    uint8_t currFragmentIdx = 0;
    size_t currMaxPacketSize = 0;
    std::vector<uint8_t*> fragments;
public:
    void encodePacket(const uint8_t *buf,const size_t size) {
        assert(size <= MAX_PAYLOAD_SIZE);
        // Use FEC_K==0 to not only disable FEC, but also the RX queue on the RX
        if(fec.FEC_K == 0) {
            const auto nonce=WBDataHeader::calculateNonce(currBlockIdx, currFragmentIdx);
            //WBDataPacket wbDataPacket{nonce, buf, size};
            //outputDataCallback(wbDataPacket);
            outputDataCallback(nonce,buf,size);
            currBlockIdx++;
            return;
        }
        FECDataHeader dataHeader(size);
        // write the size of the data part into each primary fragment.
        // This is needed for the 'up to n bytes' workaround
        memcpy(fragments[currFragmentIdx], &dataHeader, sizeof(dataHeader));
        // write the actual data
        memcpy(fragments[currFragmentIdx] + sizeof(dataHeader), buf, size);
        // zero out the remaining bytes such that FEC always sees zeroes
        // same is done on the rx. These zero bytes are never transmitted via wifi
        const auto writtenDataSize= sizeof(FECDataHeader) + size;
        memset(fragments[currFragmentIdx] + writtenDataSize, '\0', MAX_FEC_PAYLOAD - writtenDataSize);

        // send primary fragments immediately before calculating the FECs
        send_block_fragment(sizeof(dataHeader) + size);
        // the packet size for FEC encoding is determined by calculating the max of all primary fragments in this block.
        // Since the rest of the bytes are zeroed out we can run FEC with dynamic packet size.
        // As long as the deviation in packet size of primary fragments isn't too high the loss in raw bandwidth is negligible
        // Note,the loss in raw bandwidth comes from the size of the FEC secondary packets, which always has to be the max of all primary fragments
        // Not from the primary fragments, they are transmitted without the "zeroed out" part
        currMaxPacketSize = std::max(currMaxPacketSize, sizeof(dataHeader) + size);
        currFragmentIdx += 1;

        //std::cout<<"Fragment index is "<<(int)fragment_idx<<"FEC_K"<<(int)FEC_K<<"\n";
        if (currFragmentIdx < fec.FEC_K) {
            return;
        }
        // once enough data has been buffered, create all the secondary fragments
        //fecEncode((const uint8_t **) block, block + FEC_K, max_packet_size);
        fec_encode(currMaxPacketSize, (const unsigned char**)fragments.data(), fec.N_PRIMARY_FRAGMENTS, (unsigned char**)&fragments[fec.FEC_K], fec.N_SECONDARY_FRAGMENTS);
        //fecEncode(max_packet_size,fragments,N_PRIMARY_FRAGMENTS,N_SECONDARY_FRAGMENTS);

        // and send all the secondary fragments one after another
        while (currFragmentIdx < fec.FEC_N) {
            send_block_fragment(currMaxPacketSize);
            currFragmentIdx += 1;
        }
        currBlockIdx += 1;
        currFragmentIdx = 0;
        currMaxPacketSize = 0;
    }

    // returns true if the block_idx has reached its maximum
    // You want to send a new session key in this case
    bool resetOnOverflow() {
        if (currBlockIdx > WBDataHeader::MAX_BLOCK_IDX) {
            currBlockIdx = 0;
            currFragmentIdx=0;
            return true;
        }
        return false;
    }
    // add as many "empty packets" as needed until the block is done
    // if the block is already done,return immediately
    void finishCurrentBlock(){
        uint8_t emptyPacket[0];
        while(currFragmentIdx != 0){
            encodePacket(emptyPacket,0);
        }
    }
    // returns true if the last block was already fully processed.
    // in this case, you don't need to finish the current block until you put data in the next time
    // also, in the beginning the pipeline is already flushed due to no data packets yet
    bool isAlreadyInFinishedState()const{
        return currFragmentIdx == 0;
    }
private:
    // construct WB data packet, from either primary or secondary fragment
    // then forward via the callback
    void send_block_fragment(const std::size_t packet_size) const {
        const auto nonce=WBDataHeader::calculateNonce(currBlockIdx, currFragmentIdx);
        const uint8_t *dataP = fragments[currFragmentIdx];
        //WBDataPacket packet{nonce, dataP, packet_size};
        //outputDataCallback(packet);
        outputDataCallback(nonce,dataP,packet_size);
    }
};

// This encapsulates everything you need when working on a single FEC block on the receiver
// for example, addFragment() or pullAvailablePrimaryFragments()
// it also provides convenient methods to query if the block is fully forwarded
// or if it is ready for the FEC reconstruction step.
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
    // returns the indices for all primary fragments that have not yet been forwarded and are available (already received or reconstructed). Once an index is returned here, it won't be returned again
    // (Therefore, as long as you immediately forward all primary fragments returned here,everything happens in order)
    // @param breakOnFirstGap : if true (default), stop on the first gap (missing packet). Else, keep going, skipping packets with gaps. Use this parameter if
    // you need to forward everything left on a block before getting rid of it.
    std::vector<uint8_t> pullAvailablePrimaryFragments(const bool breakOnFirstGap= true){
        std::vector<uint8_t> ret;
        for(int i=nAlreadyForwardedPrimaryFragments; i < fec.FEC_K; i++){
            if(!hasFragment(i)){
                if(breakOnFirstGap){
                    break;
                }else{
                    continue;
                }
            }
            ret.push_back(i);
        }
        // make sure these indices won't be returned again
        nAlreadyForwardedPrimaryFragments+=(int)ret.size();
        return ret;
    }
    const uint8_t* getDataPrimaryFragment(const uint8_t fragmentIdx){
        assert(fragmentIdx<fec.FEC_K);
        assert(fragment_map[fragmentIdx]==AVAILABLE);
        return fragments[fragmentIdx].data();
    }
    int getNAvailableFragments()const{
        return nAvailablePrimaryFragments+nAvailableSecondaryFragments;
    }
    // make sure to check if enough secondary fragments are available before calling this method !
    // reconstructing only part of the missing data is not supported !
    // return: the n of reconstructed packets
    int reconstructAllMissingData(){
        //std::cout<<"reconstructAllMissingData"<<nAvailablePrimaryFragments<<" "<<nAvailableSecondaryFragments<<" "<<fec.FEC_K<<"\n";
        // NOTE: FEC does only work if nPrimaryFragments+nSecondaryFragments>=FEC_K
        assert(nAvailablePrimaryFragments+nAvailableSecondaryFragments>=fec.FEC_K);
        // also do not reconstruct if reconstruction is not needed
        assert(nAvailablePrimaryFragments<fec.FEC_K && nAvailableSecondaryFragments>0);
        // now bring it into a format that the c-style fec implementation understands
        std::vector<uint8_t*> primaryFragmentsData;
        std::vector<unsigned int> indicesMissingPrimaryFragments;
        for(int i=0;i<fec.FEC_K;i++){
            primaryFragmentsData.push_back(fragments[i].data());
            // if primary fragment is not available,add its index to the list of missing primary fragments
            if(fragment_map[i]!=AVAILABLE){
                indicesMissingPrimaryFragments.push_back(i);
            }
        }
        // each FEC packet has the size of max(size of primary fragments)
        std::size_t maxPacketSizeOfThisBlock=0;
        std::vector<uint8_t*> secondaryFragmentsData;
        std::vector<unsigned int> indicesAvailableSecondaryFragments;
        for(int i=0;i<fec.N_SECONDARY_FRAGMENTS;i++){
            const int idx=fec.FEC_K+i;
            secondaryFragmentsData.push_back(fragments[idx].data());
            // if secondary fragment is available,add its index to the list of secondary packets that will be used for reconstruction
            if(fragment_map[idx]==AVAILABLE){
                indicesAvailableSecondaryFragments.push_back(i);
                maxPacketSizeOfThisBlock=originalSizeOfFragments.at(idx);
            }
        }
        fec_decode(maxPacketSizeOfThisBlock, primaryFragmentsData.data(), fec.FEC_K, secondaryFragmentsData.data(), indicesAvailableSecondaryFragments.data(), indicesMissingPrimaryFragments.data(), indicesAvailableSecondaryFragments.size());
        // after the decode step,all previously missing primary fragments have become available - mark them as such
        for(const auto idx:indicesMissingPrimaryFragments){
            fragment_map[idx]=AVAILABLE;
        }
        // n of reconstructed packets
        return indicesMissingPrimaryFragments.size();
    }
private:
    //reference to the FEC decoder (needed for k,n). Doesn't change
    const FEC& fec;
public:
    // the block idx marks which block this element currently refers to
    uint64_t block_idx=0;
private:
    // n of primary fragments that are already sent out
    int nAlreadyForwardedPrimaryFragments=0;
    // for each fragment (via fragment_idx) store if it has been received yet
    enum FragmentStatus{UNAVAILABLE=0,AVAILABLE=1};
    // size of all these vectors is always FEC_N
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
class FECDecoder{
public:
    // If K,N is known at construction time
    FECDecoder(int k, int n){
        fec_init();
        resetNewSession(k,n);
    }
    // If K,N is not known at construction time. Don't forget to call resetNewSession() in this case !
    FECDecoder(){
        fec_init();
    }
    ~FECDecoder() = default;
    typedef std::function<void(const uint8_t * payload,std::size_t payloadSize)> SEND_DECODED_PACKET;
    // WARNING: Don't forget to register this callback !
    SEND_DECODED_PACKET mSendDecodedPayloadCallback;
private:
    //K,N can change on the receiver side !
    std::unique_ptr<FEC> fec=nullptr;
public:
    // FEC K,N is fixed per session
    void resetNewSession(const int K,const int N) {
        seq = 0;
        // rx ring part. Remove anything still in the queue
        rx_ring_front = 0;
        rx_ring_alloc = 0;
        last_known_block = (uint64_t) -1;
        // re-allocate the rx ring if new FEC parameters are used
        if(fec== nullptr || fec->FEC_K!=K || fec->FEC_N != N){
            fec=std::make_unique<FEC>(K,N);
            for(int i=0;i<RX_RING_SIZE;i++){
                rx_ring[i]=std::make_unique<RxBlock>(*fec);
            }
        }
        // we now have information about FEC K,N since it came with the encryption packet
        for(auto& rxBlock:rx_ring){
            rxBlock->repurpose();
        }
    }
    // returns false if the packet fragment index doesn't match the set FEC parameters (which should never happen !)
    bool validateAndProcessPacket(const uint64_t nonce, const std::vector<uint8_t>& decrypted){
        if(fec==nullptr){
            std::cout<<"FEC K,N is not set yet\n";
            return false;
        }
        // Use FEC_K==0 to completely disable FEC and skip the RX queue
        if(fec->FEC_K == 0) {
            const auto packetSeq=WBDataHeader::calculateBlockIdx(nonce);
            processRawDataBlockFecDisabled(packetSeq,decrypted);
            return true;
        }
        // normal FEC processing
        const uint64_t block_idx=WBDataHeader::calculateBlockIdx(nonce);
        const uint8_t fragment_idx=WBDataHeader::calculateFragmentIdx(nonce);

        // Should never happen due to generating new session key on tx side
        if (block_idx > WBDataHeader::MAX_BLOCK_IDX) {
            std::cerr<<"block_idx overflow\n";
            return false;
        }
        // fragment index must be in the range [0,...,FEC_N[
        if (fragment_idx >= fec->FEC_N) {
            std::cerr<<"invalid fragment_idx:"<<fragment_idx<<"\n";
            return false;
        }
        processFECBlockWitRxQueue(block_idx,fragment_idx,decrypted);
        return true;
    }
private:
    uint64_t seq = 0;
    /**
     * For this Block,
     * starting at the primary fragment we stopped on last time,
     * forward as many primary fragments as they are available until there is a gap
     * @param breakOnFirstGap : if true, stop on the first gap in all primary fragments. Else, keep going skipping packets with gaps
     */
    void forwardMissingPrimaryFragmentsIfAvailable(RxBlock& rxRingItem, const bool breakOnFirstGap= true){
        const auto indices=rxRingItem.pullAvailablePrimaryFragments(breakOnFirstGap);
        for(auto index:indices){
            forwardPrimaryFragment(rxRingItem,index);
        }
    }
    /**
     * Forward the primary (data) fragment at index fragmentIdx via the output callback
     */
    void forwardPrimaryFragment(RxBlock& rxRingItem, const uint8_t fragmentIdx){
        //std::cout<<"forwardPrimaryFragment"<<(int)fragmentIdx<<"\n";
        assert(rxRingItem.hasFragment(fragmentIdx));
        const uint8_t* primaryFragment= rxRingItem.getDataPrimaryFragment(fragmentIdx);
        const FECDataHeader *packet_hdr = (FECDataHeader*) primaryFragment;

        const uint8_t *payload = primaryFragment + sizeof(FECDataHeader);
        const uint16_t packet_size = packet_hdr->get();
        const uint64_t packet_seq = rxRingItem.block_idx * fec->FEC_K + fragmentIdx;

        if (packet_seq > seq + 1) {
            const auto packetsLost=(packet_seq - seq - 1);
            //std::cerr<<packetsLost<<"packets lost\n";
            count_p_lost += packetsLost;
        }
        seq = packet_seq;
        if (packet_size > MAX_PAYLOAD_SIZE) {
            // this should never happen !
            std::cerr<<"corrupted packet on FECDecoder out "<<seq<<"\n";
        } else {
            // we use packets of size 0 to flush the tx pipeline
            if(packet_size>0){
                mSendDecodedPayloadCallback(payload, packet_size);
            }
        }
    }
private:
    static constexpr auto RX_RING_SIZE = 20;
    // Here is everything you need when using the RX queue to account for packet re-ordering due to multiple wifi cards
    std::array<std::unique_ptr<RxBlock>,RX_RING_SIZE> rx_ring;
    int rx_ring_front = 0; // current packet
    int rx_ring_alloc = 0; // number of allocated entries
    uint64_t last_known_block = ((uint64_t) -1);  //id of last known block
    //
    static inline int modN(int x, int base) {
        return (base + (x % base)) % base;
    }
    // removes the first (oldest) element
    // returns the index of the removed element
    int rxRingPopFront(){
        const auto ret=rx_ring_front;
        rx_ring_front = modN(rx_ring_front + 1, RX_RING_SIZE);
        rx_ring_alloc -= 1;
        assert(rx_ring_alloc >= 0);
        return ret;
    }
    // makes space for 1 new element
    // return its index (this is now the latest element)
    int rxRingPushBack(){
        int idx = modN(rx_ring_front + rx_ring_alloc, RX_RING_SIZE);
        rx_ring_alloc += 1;
        assert(rx_ring_alloc<=RX_RING_SIZE);
        return idx;
    }
    // if enough space is available, same like push back
    // if not enough space is available,it drops the oldest block, and also sends any fragments of this block that are not forwarded yet
    int rxRingPushBackSafe() {
        if (rx_ring_alloc < RX_RING_SIZE) {
            return rxRingPushBack();
        }
        //Ring overflow. This means that there are more unfinished blocks than ring size
        //Possible solutions:
        //1. Increase ring size. Do this if you have large variance of packet travel time throught WiFi card or network stack.
        //   Some cards can do this due to packet reordering inside, diffent chipset and/or firmware or your RX hosts have different CPU power.
        //2. Reduce packet injection speed or try to unify RX hardware.

        // remove the oldest block
        auto oldestBlockIdx=rxRingPopFront();
        auto oldestBlock=*rx_ring[oldestBlockIdx];
        std::cerr<<"Forwarding block that is not yet fully finished "<<oldestBlock.block_idx<<" with n fragments"<<oldestBlock.getNAvailableFragments()<<"\n";
        forwardMissingPrimaryFragmentsIfAvailable(oldestBlock,false);
        //
        return rxRingPushBack();
    }
    // If block is already known and not in the ring anymore return -1
    // else if block is already in the ring return its index or if block is not yet
    // in the ring add as many blocks as needed and then return its index
    int get_block_ring_idx(const uint64_t block_idx) {
        // check if block is already in the ring
        for (int i = rx_ring_front, c = rx_ring_alloc; c > 0; i = modN(i + 1, FECDecoder::RX_RING_SIZE), c--) {
            if (rx_ring[i]->block_idx == block_idx) return i;
        }

        // check if block is already known and not in the ring then it is already processed
        if (last_known_block != (uint64_t) -1 && block_idx <= last_known_block) {
            return -1;
        }
        // add as many blocks as we need ( the rx ring mustn't have any gaps between the block indices)
        const int new_blocks = (int) std::min(last_known_block != (uint64_t) -1 ? block_idx - last_known_block : 1,
                                        (uint64_t) FECDecoder::RX_RING_SIZE);
        assert (new_blocks > 0);

        last_known_block = block_idx;
        int ring_idx = -1;

        for (int i = 0; i < new_blocks; i++) {
            ring_idx = rxRingPushBackSafe();
            const auto newBlockIdx=block_idx + i + 1 - new_blocks;
            rx_ring[ring_idx]->repurpose(newBlockIdx);
        }
        return ring_idx;
    }

    void processFECBlockWitRxQueue(const uint64_t block_idx, const uint8_t fragment_idx, const std::vector<uint8_t>& decrypted){
        const int ring_idx = get_block_ring_idx(block_idx);
        //ignore already processed blocks
        if (ring_idx < 0) return;
        // cannot be nullptr
        RxBlock& block = *rx_ring[ring_idx].get();
        // ignore already processed fragments
        if(block.hasFragment(fragment_idx)){
            return;
        }
        block.addFragment(fragment_idx, decrypted.data(), decrypted.size());
        //std::cout<<"Allocated entries "<<rx_ring_alloc<<"\n";

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
                count_p_fec_recovered+=block.reconstructAllMissingData();
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
                    count_p_fec_recovered+=block.reconstructAllMissingData();
                    forwardMissingPrimaryFragmentsIfAvailable(block);
                    assert(block.allPrimaryFragmentsHaveBeenForwarded());
                }
                // remove block
                rxRingPopFront();
            }
        }
    }
    void processRawDataBlockFecDisabled(const uint64_t packetSeq,const std::vector<uint8_t>& decrypted){
        // here we buffer nothing, but still make sure that packets only are forwarded with increasing sequence number
        // If one RX was used only, this would not be needed. But with multiple RX we can have duplicates
        if(seq!=0 && packetSeq<=seq){
            // either duplicate or we are already ahead of this index
            return;
        }
        //also write lost packet count in this mode
        if (packetSeq > seq + 1) {
            const auto packetsLost=(packetSeq - seq - 1);
            //std::cerr<<packetsLost<<"packets lost\n";
            count_p_lost += packetsLost;
        }
        mSendDecodedPayloadCallback(decrypted.data(), decrypted.size());
        seq=packetSeq;
    }
public:
    // By doing so you are telling the pipeline:
    // It makes no sense to hold on to any blocks. Future packets won't help you to recover any blocks that might still be in the pipeline
    // For example, if the RX doesn't receive anything for N ms any data that is going to arrive will not have a smaller or equal block index than the blocks that are currently in the queue
    void flushRxRing(){
        std::cout<<"Flushing pipeline\n";
        while(rx_ring_alloc>0){
            auto idx=rxRingPopFront();
            forwardMissingPrimaryFragmentsIfAvailable(*rx_ring[idx],false);
        }
    }
protected:
    uint64_t count_p_fec_recovered=0;
    uint64_t count_p_lost=0;
    //
};


#endif //WIFIBROADCAST_FEC_HPP
