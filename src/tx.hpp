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

#include "Encryption.hpp"
#include "FEC.hpp"
#include "Helper.hpp"


// Pcap Transmitter injects packets into the wifi adapter using pcap
// It uses an UDP port as input for the data stream
// Each input UDP port has to be assigned with a Unique ID to differentiate between streams on the RX
class PcapTransmitter: public FECEncoder{
public:
    PcapTransmitter(RadiotapHeader radiotapHeader, int k, int m, const std::string &keypair, uint8_t radio_port,
                    int udp_port,const std::string &wlan);
    ~PcapTransmitter();
private:
    // send the current session key via WIFI (located in mEncryptor)
    void send_session_key();
    // process the input data stream
    void send_packet(const uint8_t *buf, size_t size);
    // inject packet by prefixing data with the current IEE and Radiotap header
    void inject_packet(const uint8_t *buf, size_t size);
    // for the FEC encoder
    void sendFecBlock(const WBDataPacket &xBlock);
    // the radio port is what is used as an index to multiplex multiple streams (telemetry,video,...)
    // into the one wfb stream
    const uint8_t RADIO_PORT;
    // the rx socket is set by opening the right UDP port
    int mRxSocket;
    // Used to encrypt the packets
    Encryptor mEncryptor;
    // Used to inject packets
    Ieee80211Header mIeee80211Header;
    // this one never changes,also used to inject packets
    const RadiotapHeader mRadiotapHeader;
    uint16_t ieee80211_seq=0;
    pcap_t* ppcap;
public:
    // run as long as nothing goes completely wrong
    void loop();
};

