// -*- C++ -*-
//
// Copyright (C) 2017, 2018 Vasily Evseenko <svpcom@p2ptech.org>

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

#include <assert.h>
#include <stdio.h>
#include <inttypes.h>
#include <time.h>
#include <limits.h>

#include <memory>
#include <string>
#include <chrono>
#include <sstream>

#include "wifibroadcast.hpp"
#include "FEC.hpp"

#include "Helper.hpp"
#include "Encryption.hpp"

namespace TestFEC{
    // test the FECEncoder / FECDecoder tuple
    static void testWithoutPacketLoss(const int k, const int n, const std::vector<std::vector<uint8_t>>& testIn){
        std::cout<<"Test K:"<<k<<" N:"<<n<<" N_PACKETS:"<<testIn.size()<<"\n";
        FECEncoder encoder(k,n);
        FECDecoder decoder(k,n);
        std::vector<std::vector<uint8_t>> testOut;

        const auto cb1=[&decoder](const WBDataPacket &xBlock)mutable {
            decoder.processPacket(xBlock.header,std::vector<uint8_t>(xBlock.payload,xBlock.payload+xBlock.payloadSize));
        };
        const auto cb2=[&testOut](const uint8_t * payload,std::size_t payloadSize)mutable{
            testOut.emplace_back(payload,payload+payloadSize);
        };
        encoder.callback=cb1;
        decoder.callback=cb2;
        // If there is no data loss the packets should arrive immediately
        for(std::size_t i=0;i<testIn.size();i++){
            const auto& in=testIn[i];
            encoder.encodePacket(in.data(),in.size());
            const auto& out=testOut[i];
            assert(GenericHelper::compareVectors(in,out)==true);
        }
    }

    // No packet loss
    // Fixed packet size
    static void testWithoutPacketLossFixedPacketSize(const int k, const int n, const std::size_t N_PACKETS){
        std::vector<std::vector<uint8_t>> testIn;
        for(std::size_t i=0;i<N_PACKETS;i++){
            testIn.push_back(GenericHelper::createRandomDataBuffer(1024));
        }
        testWithoutPacketLoss(k, n, testIn);
    }

    // No packet loss
    // Dynamic packet size (up to N bytes)
    static void testWithoutPacketLossDynamicPacketSize(const int k, const int n, const std::size_t N_PACKETS){
        std::vector<std::vector<uint8_t>> testIn;
        for(std::size_t i=0;i<N_PACKETS;i++){
            const auto size=(rand() % MAX_PAYLOAD_SIZE)+1;
            testIn.push_back(GenericHelper::createRandomDataBuffer(size));
        }
        testWithoutPacketLoss(k, n, testIn);
    }

    // test with packet loss
    // but only drop one data packet per sequence
    static void testWithPacketLossButEverythingIsRecoverable(const int k, const int n, const std::vector<std::vector<uint8_t>>& testIn,const int DROP_MODE) {
        assert(testIn.size() % n==0);
        std::cout << "Test (with packet loss) K:" << k << " N:" << n << " N_PACKETS:" << testIn.size() <<" DROP_MODE:"<<DROP_MODE<< "\n";
        FECEncoder encoder(k, n);
        FECDecoder decoder(k, n);
        std::vector <std::vector<uint8_t>> testOut;
        const auto cb1 = [&decoder,n,k,DROP_MODE](const WBDataPacket &xBlock)mutable {
            const auto blockIdx=WBDataHeader::calculateBlockIdx(xBlock.header.nonce);
            const auto fragmentIdx=WBDataHeader::calculateFragmentIdx(xBlock.header.nonce);
            if(DROP_MODE==0){
                // drop all FEC correction packets but no data packets (everything should be still recoverable
                if(fragmentIdx>=k){
                    std::cout<<"Dropping FEC-CORRECTION packet:["<<blockIdx<<","<<(int)fragmentIdx<<"]\n";
                    return;
                }
            }else if(DROP_MODE==1){
                // drop 1 data packet and let FEC do its magic
                if(fragmentIdx==0){
                    std::cout<<"Dropping FEC-DATA packet:["<<blockIdx<<","<<(int)fragmentIdx<<"]\n";
                }
            }else if(DROP_MODE==2){
                // drop 1 data packet and 1 FEC packet but that still shouldn't pose any issues
                if(fragmentIdx==0){
                    std::cout<<"Dropping FEC-DATA packet:["<<blockIdx<<","<<(int)fragmentIdx<<"]\n";
                }else if(fragmentIdx==k-1){
                    std::cout<<"Dropping FEC-CORRECTION packet:["<<blockIdx<<","<<(int)fragmentIdx<<"]\n";
                }
            }
            decoder.processPacket(xBlock.header,std::vector<uint8_t>(xBlock.payload, xBlock.payload + xBlock.payloadSize));
        };
        const auto cb2 = [&testOut](const uint8_t *payload, std::size_t payloadSize)mutable {
            testOut.emplace_back(payload, payload + payloadSize);
        };
        encoder.callback = cb1;
        decoder.callback = cb2;
        for (std::size_t i = 0; i < testIn.size(); i++) {
            const auto &in = testIn[i];
            encoder.encodePacket(in.data(), in.size());
            // now check if everything already sent arrived
            // since there can be packet loss, you might have to wait for the fec to do its magic (latency)
            if(i % n ==0 && i>0){
                for(std::size_t j=0;j<i;j++){
                    const auto &in = testIn[j];
                    const auto &out = testOut[j];
                    assert(GenericHelper::compareVectors(in, out) == true);
                }
            }
        }
        // now check again if everything is still okay
        for (std::size_t i = 0; i < testIn.size(); i++) {
            const auto &in = testIn[i];
            const auto &out = testOut[i];
            assert(GenericHelper::compareVectors(in, out) == true);
        }
    }

    static void test3(const int k,const int n,const std::size_t N_PACKETS,const int DROP_MODE){
        std::vector<std::vector<uint8_t>> testIn;
        for(std::size_t i=0;i<N_PACKETS;i++){
            const auto size=(rand() % MAX_PAYLOAD_SIZE)+1;
            testIn.push_back(GenericHelper::createRandomDataBuffer(size));
        }
        testWithPacketLossButEverythingIsRecoverable(k, n, testIn,DROP_MODE);
    }

}

namespace TestEncryption{
    static void test(){
        Encryptor encryptor("gs.key");
        Decryptor decryptor("drone.key");
        encryptor.makeSessionKey();
        assert(decryptor.onNewPacketWfbKey((uint8_t*)&encryptor.sessionKeyPacket)==true);

        const auto data=GenericHelper::createRandomDataBuffer(MAX_PAYLOAD_SIZE);
        const uint64_t block_idx = 0;
        const uint8_t fragment_idx = 0;
        const auto nonce=WBDataHeader::calculateNonce(block_idx,fragment_idx);
        const WBDataPacket wbDataPacket{nonce,data.data(),data.size()};

        const auto encrypted= encryptor.makeEncryptedPacketIncludingHeader(wbDataPacket);

        const auto decrypted=decryptor.decryptPacket(wbDataPacket.header,&encrypted[sizeof(WBDataHeader)],encrypted.size()-sizeof(WBDataHeader));

        assert(decrypted!=std::nullopt);
        assert(GenericHelper::compareVectors(data,*decrypted) == true);
    }
}

int main(int argc, char *argv[]){
    std::cout<<"Tests for Wifibroadcast\n";
    try {
        std::cout<<"Testing FEC\n";
        // first, test with fec disabled
        TestFEC::testWithoutPacketLossDynamicPacketSize(0, 0, 1200);
        // now with FEC enabled
        int k=0;
        int n=0;
        for(int i=0;i<3;i++){
            if(i==0){
                k=4;
                n=8;
            }else if(i==1){
                k=6;
                n=12;
            }else if(i==2){
                k=8;
                n=16;
            }
            TestFEC::testWithoutPacketLossFixedPacketSize(k, n, 1200);
            TestFEC::testWithoutPacketLossDynamicPacketSize(k, n, 1200);
            //TestFEC::test3(k,n,1200,0);
            TestFEC::test3(k,n,1200,2);
        }
        //
        std::cout<<"Testing Encryption\n";
        TestEncryption::test();

    }catch (std::runtime_error &e) {
        fprintf(stderr, "Error: %s\n", e.what());
        exit(1);
    }
    std::cout<<"Tests Passing\n";
    return 0;
}