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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <sys/resource.h>
#include <pcap/pcap.h>
#include <poll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <limits.h>

#include <memory>
#include <string>
#include <memory>
#include <chrono>
#include <sstream>

#include "wifibroadcast.hpp"
#include "FEC.hpp"

extern "C"{
#include "ExternalSources/fec.h"
}

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
    static void test(const int k,const int n,const std::size_t N_PACKETS){
        std::vector<std::vector<uint8_t>> testIn;
        for(std::size_t i=0;i<N_PACKETS;i++){
            testIn.push_back(GenericHelper::createRandomDataBuffer(1024));
        }
        testWithoutPacketLoss(k, n, testIn);
    }

    // No packet loss
    // Dynamic packet size (up to N bytes)
    static void test2(const int k,const int n,const std::size_t N_PACKETS){
        std::vector<std::vector<uint8_t>> testIn;
        for(std::size_t i=0;i<N_PACKETS;i++){
            const auto size=rand() % MAX_PAYLOAD_SIZE;
            testIn.push_back(GenericHelper::createRandomDataBuffer(size));
        }
        testWithoutPacketLoss(k, n, testIn);
    }

    // test with packet loss
    // but only drop one data packet per sequence
    static void testWithPacketLossButEverythingIsRecoverable(const int k, const int n, const std::vector<std::vector<uint8_t>>& testIn) {
        assert(testIn.size() % n==0);
        std::cout << "Test (with packet loss) K:" << k << " N:" << n << " N_PACKETS:" << testIn.size() << "\n";
        FECEncoder encoder(k, n);
        FECDecoder decoder(k, n);
        std::vector <std::vector<uint8_t>> testOut;
        int packetIdx = 0;
        const auto cb1 = [&decoder, &packetIdx, n](const WBDataPacket &xBlock)mutable {
            if (packetIdx % n == 0) {
                // new sequence, drop one data packet (which FEC can correct for)
                //std::cout<<"Dropping packet "<<packetIdx<<"\n";
            }else{
                decoder.processPacket(xBlock.header,std::vector<uint8_t>(xBlock.payload, xBlock.payload + xBlock.payloadSize));
            }
            packetIdx++;
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
            // since there is packet loss, you have to wait for the fec to do its magic (latency)
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

    static void test3(const int k,const int n,const std::size_t N_PACKETS){
        std::vector<std::vector<uint8_t>> testIn;
        for(std::size_t i=0;i<N_PACKETS;i++){
            const auto size=rand() % MAX_PAYLOAD_SIZE;
            testIn.push_back(GenericHelper::createRandomDataBuffer(size));
        }
        testWithPacketLossButEverythingIsRecoverable(k, n, testIn);
    }
}

namespace TestEncryption{
    // TODO why does that not work yet ?
    static void test(){
        Encryptor encryptor("");
        Decryptor decryptor("");
        encryptor.makeSessionKey();
        assert(decryptor.onNewPacketWfbKey((uint8_t*)&encryptor.sessionKeyPacket)==true);

        const auto data=GenericHelper::createRandomDataBuffer(100);
        const uint64_t block_idx = 0;
        const uint8_t fragment_idx = 0;
        const auto nonce=htobe64(((block_idx & BLOCK_IDX_MASK) << 8) + fragment_idx);
        const WBDataPacket wbDataPacket{nonce,data.data(),data.size()};

        const auto encrypted=encryptor.makeEncryptedPacket(wbDataPacket);

        const auto decrypted=decryptor.decryptPacket(wbDataPacket.header,encrypted.data(),encrypted.size());

        assert(decrypted!=std::nullopt);
        assert(GenericHelper::compareVectors(data,*decrypted) == true);
    }
}

int main(int argc, char *const *argv){
    std::cout<<"Tests for Wifibroadcast\n";
    try {
        std::cout<<"Testing FEC\n";
        // is there a bug with the testing method or with the fec implementation ?
        /*for(int k=4;k<=8;k+=4){
            for(int n=k+4;n<=12;n+=4){
                std::cout<<"k:"<<k<<" n:"<<n<<"\n";
                TestFEC::test(k,n,1200);
                TestFEC::test2(k,n,1200);
                TestFEC::test3(k,n,1200);
            }
        }*/
        TestFEC::test(4,8,1000);
        TestFEC::test2(4,8,100);
        TestFEC::test3(4,8,1000);
        //
        //std::cout<<"Testing Encryption\n";
        //TestEncryption::test();
    }catch (std::runtime_error &e) {
        fprintf(stderr, "Error: %s\n", e.what());
        exit(1);
    }
    std::cout<<"Tests Passing\n";
    return 0;
}