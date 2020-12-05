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

#include "wifibroadcast.hpp"
#include "rx.hpp"
extern "C"{
#include "ExternalSources/fec.h"
}

namespace Helper{
    // copy paste from svpcom
    // I think this one opens the rx interface with pcap and then sets a filter such that only packets pass through for the selected radio port
    static pcap_t* openRxWithPcap(const std::string& wlan,const int radio_port){
        pcap_t* ppcap;
        char errbuf[PCAP_ERRBUF_SIZE];
        ppcap = pcap_create(wlan.c_str(), errbuf);
        if (ppcap == NULL) {
            throw std::runtime_error(StringFormat::convert("Unable to open interface %s in pcap: %s", wlan.c_str(), errbuf));
        }
        if (pcap_set_snaplen(ppcap, 4096) != 0) throw std::runtime_error("set_snaplen failed");
        if (pcap_set_promisc(ppcap, 1) != 0) throw std::runtime_error("set_promisc failed");
        //if (pcap_set_rfmon(ppcap, 1) !=0) throw runtime_error("set_rfmon failed");
        if (pcap_set_timeout(ppcap, -1) != 0) throw std::runtime_error("set_timeout failed");
        //if (pcap_set_buffer_size(ppcap, 2048) !=0) throw runtime_error("set_buffer_size failed");
        if (pcap_activate(ppcap) != 0) throw std::runtime_error(StringFormat::convert("pcap_activate failed: %s", pcap_geterr(ppcap)));
        if (pcap_setnonblock(ppcap, 1, errbuf) != 0) throw std::runtime_error(StringFormat::convert("set_nonblock failed: %s", errbuf));

        int link_encap = pcap_datalink(ppcap);
        struct bpf_program bpfprogram{};
        std::string program;
        switch (link_encap) {
            case DLT_PRISM_HEADER:
                fprintf(stderr, "%s has DLT_PRISM_HEADER Encap\n", wlan.c_str());
                program = StringFormat::convert("radio[0x4a:4]==0x13223344 && radio[0x4e:2] == 0x55%.2x", radio_port);
                break;

            case DLT_IEEE802_11_RADIO:
                fprintf(stderr, "%s has DLT_IEEE802_11_RADIO Encap\n", wlan.c_str());
                program = StringFormat::convert("ether[0x0a:4]==0x13223344 && ether[0x0e:2] == 0x55%.2x", radio_port);
                break;

            default:
                throw std::runtime_error(StringFormat::convert("unknown encapsulation on %s", wlan.c_str()));
        }
        if (pcap_compile(ppcap, &bpfprogram, program.c_str(), 1, 0) == -1) {
            throw std::runtime_error(StringFormat::convert("Unable to compile %s: %s", program.c_str(), pcap_geterr(ppcap)));
        }
        if (pcap_setfilter(ppcap, &bpfprogram) == -1) {
            throw std::runtime_error(StringFormat::convert("Unable to set filter %s: %s", program.c_str(), pcap_geterr(ppcap)));
        }
        pcap_freecode(&bpfprogram);
        return ppcap;
    }
    static void writeAntennaStats(antenna_stat_t& antenna_stat,const sockaddr_in *sockaddr, uint8_t wlan_idx, const uint8_t *ant, const int8_t *rssi){
        for (int i = 0; i < RX_ANT_MAX && ant[i] != 0xff; i++) {
            // key: addr + port + wlan_idx + ant
            uint64_t key = 0;
            if (sockaddr != NULL && sockaddr->sin_family == AF_INET) {
                key = ((uint64_t) ntohl(sockaddr->sin_addr.s_addr) << 32 | (uint64_t) ntohs(sockaddr->sin_port) << 16);
            }

            key |= ((uint64_t) wlan_idx << 8 | (uint64_t) ant[i]);

            antenna_stat[key].addRSSI(rssi[i]);
        }
    }
}

Receiver::Receiver(const char *wlan, int wlan_idx, int radio_port, BaseAggregator *agg) : wlan_idx(wlan_idx), agg(agg) {
    ppcap=Helper::openRxWithPcap(std::string(wlan),radio_port);
    fd = pcap_get_selectable_fd(ppcap);
}


Receiver::~Receiver() {
    close(fd);
    pcap_close(ppcap);
}


void Receiver::loop_iter() {
    for (;;) // loop while incoming queue is not empty
    {
        struct pcap_pkthdr hdr{};
        const uint8_t *pkt = pcap_next(ppcap, &hdr);
        if (pkt == nullptr) {
            break;
        }
        //
        //printf("PacketTime:%ld.%06ld\n", hdr.ts.tv_sec, hdr.ts.tv_usec);

        int pktlen = hdr.caplen;
        // int pkt_rate = 0
        int ant_idx = 0;
        std::array<uint8_t,RX_ANT_MAX> antenna{};
        // Fill all antenna slots with 0xff (unused)
        antenna.fill(0xff);
        std::array<int8_t ,RX_ANT_MAX> rssi{};
        // Fill all rssi slots with minimum value
        rssi.fill(SCHAR_MIN);
        uint8_t flags = 0;
        struct ieee80211_radiotap_iterator iterator{};
        int ret = ieee80211_radiotap_iterator_init(&iterator, (ieee80211_radiotap_header *) pkt, pktlen, NULL);


        while (ret == 0 && ant_idx < RX_ANT_MAX) {
            ret = ieee80211_radiotap_iterator_next(&iterator);

            if (ret)
                continue;

            /* see if this argument is something we can use */

            switch (iterator.this_arg_index) {
                /*
                 * You must take care when dereferencing iterator.this_arg
                 * for multibyte types... the pointer is not aligned.  Use
                 * get_unaligned((type *)iterator.this_arg) to dereference
                 * iterator.this_arg for type "type" safely on all arches.
                 */

                // case IEEE80211_RADIOTAP_RATE:
                //     /* radiotap "rate" u8 is in
                //      * 500kbps units, eg, 0x02=1Mbps
                //      */
                //     pkt_rate = (*(uint8_t*)(iterator.this_arg))/2;
                //     break;

                case IEEE80211_RADIOTAP_ANTENNA:
                    // FIXME
                    // In case of multiple antenna stats in one packet this index will be irrelivant
                    antenna[ant_idx] = *(uint8_t *) (iterator.this_arg);
                    ant_idx += 1;
                    break;

                case IEEE80211_RADIOTAP_DBM_ANTSIGNAL:
                    // Some cards can provide rssi for multiple antennas in one packet, so we should select maximum value
                    rssi[ant_idx] = *(int8_t *) (iterator.this_arg);
                    break;

                case IEEE80211_RADIOTAP_FLAGS:
                    flags = *(uint8_t *) (iterator.this_arg);
                    break;

                default:
                    break;
            }
        }  /* while more rt headers */

        if (ret != -ENOENT && ant_idx < RX_ANT_MAX) {
            fprintf(stderr, "Error parsing radiotap header!\n");
            continue;
        }

        if (flags & IEEE80211_RADIOTAP_F_FCS) {
            pktlen -= 4;
        }

        if (flags & IEEE80211_RADIOTAP_F_BADFCS) {
            fprintf(stderr, "Got packet with bad fsc\n");
            continue;
        }

        /* discard the radiotap header part */
        pkt += iterator._max_length;
        pktlen -= iterator._max_length;

        if (pktlen > (int) Ieee80211Header::SIZE_BYTES) {
            agg->process_packet(pkt + Ieee80211Header::SIZE_BYTES, pktlen - Ieee80211Header::SIZE_BYTES, wlan_idx, antenna.data(),
                                rssi.data(), NULL);
        } else {
            fprintf(stderr, "short packet (ieee header)\n");
            continue;
        }
    }
}


Aggregator::Aggregator(const std::string &client_addr, int client_port, int k, int n, const std::string &keypair) :
FECDecoder(k,n),
        mDecryptor(keypair),
        /*fec_k(k), fec_n(n), seq(0), rx_ring_front(0), rx_ring_alloc(0), last_known_block((uint64_t) -1),*/
        count_p_all(0), count_p_dec_err(0), count_p_dec_ok(0){
    sockfd = SocketHelper::open_udp_socket_for_tx(client_addr, client_port);
    callback=std::bind(&Aggregator::sendPacketViaUDP, this, std::placeholders::_1,std::placeholders::_2);
}


Aggregator::~Aggregator() {
    close(sockfd);
}


void Aggregator::dump_stats(FILE *fp) {
    //timestamp in ms
    const uint64_t runTime=std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now()-INIT_TIME).count();

    for (auto & it : antenna_stat) {
        fprintf(fp, "%" PRIu64 "\tANT\t%" PRIx64 "\t%d:%d:%d:%d\n", runTime, it.first, it.second.count_all,
                it.second.rssi_min, it.second.rssi_sum / it.second.count_all, it.second.rssi_max);
    }
    antenna_stat.clear();

    fprintf(fp, "%" PRIu64 "\tPKT\t%u:%u:%u:%u:%u:%u\n", runTime, count_p_all, count_p_dec_err, count_p_dec_ok,
            count_p_fec_recovered, count_p_lost, count_p_bad);
    fflush(fp);

    count_p_all = 0;
    count_p_dec_err = 0;
    count_p_dec_ok = 0;
    count_p_fec_recovered = 0;
    count_p_lost = 0;
    count_p_bad = 0;
}

void Aggregator::process_packet(const uint8_t *buf,const size_t size, uint8_t wlan_idx, const uint8_t *antenna,
                                const int8_t *rssi, sockaddr_in *sockaddr) {
    count_p_all += 1;

    if (size == 0) return;

    if (size > MAX_FORWARDER_PACKET_SIZE) {
        fprintf(stderr, "long packet (fec payload)\n");
        count_p_bad += 1;
        return;
    }

    switch (buf[0]) {
        case WFB_PACKET_DATA:
            if (size < sizeof(wblock_hdr_t) + sizeof(FECDataHeader)) {
                fprintf(stderr, "short packet (fec header)\n");
                count_p_bad += 1;
                return;
            }
            break;

        case WFB_PACKET_KEY:
            if (size != sizeof(wsession_key_t)) {
                fprintf(stderr, "invalid session key packet\n");
                count_p_bad += 1;
                return;
            }
            if (mDecryptor.onNewPacketWfbKey(buf)) {
                count_p_dec_ok += 1;
                FECDecoder::reset();
            } else {
                count_p_dec_err += 1;
            }
            return;
        default:
            fprintf(stderr, "Unknown packet type 0x%x\n", buf[0]);
            count_p_bad += 1;
            return;
    }
    // FEC data or FEC correction packet
    wblock_hdr_t *block_hdr = (wblock_hdr_t *) buf;
    const auto decrypted=mDecryptor.decryptPacket(*block_hdr,&buf[sizeof(wblock_hdr_t)],size-sizeof(wblock_hdr_t));

    if(decrypted==std::nullopt){
        fprintf(stderr, "unable to decrypt packet #0x%" PRIx64 "\n", be64toh(block_hdr->nonce));
        count_p_dec_err += 1;
        return;
    }
    //const auto tmp=(FECDataHeader*)decrypted->data();
    //std::cout<<"Size Test:"<<size<<" "<<((int)decrypted->size())<<" "<<((int)tmp->get())<<"\n";
    // hmm somehow this test failed
    //assert(decrypted->size()==tmp->get()+sizeof(wpacket_hdr_t));
    // size should only match on data packets
    /*if(decrypted->size()!=tmp->get()+sizeof(FECDataHeader)){
        std::cout<<"Something wrong with size:"<<size<<" "<<((int)decrypted->size())<<" "<<((int)tmp->get())<<"\n";
    }else{
        std::cout<<"Sizes are:"<<size<<" "<<((int)decrypted->size())<<" "<<((int)tmp->get())<<"\n";
    }*/

    count_p_dec_ok += 1;
    //log_rssi(sockaddr, wlan_idx, antenna, rssi);
    Helper::writeAntennaStats(antenna_stat,sockaddr,wlan_idx,antenna,rssi);

    assert(decrypted->size() <= MAX_FEC_PAYLOAD);

    FECDecoder::processPacket(*block_hdr, *decrypted);
}

void
radio_loop(int argc, char *const *argv, int optind, int radio_port, std::shared_ptr<BaseAggregator> agg,const std::chrono::milliseconds log_interval) {
    int nfds = std::min(argc - optind, MAX_RX_INTERFACES);
    std::chrono::steady_clock::time_point log_send_ts{};
    struct pollfd fds[MAX_RX_INTERFACES];
    Receiver *rx[MAX_RX_INTERFACES];

    memset(fds, '\0', sizeof(fds));

    for (int i = 0; i < nfds; i++) {
        rx[i] = new Receiver(argv[optind + i], i, radio_port, agg.get());
        fds[i].fd = rx[i]->getfd();
        fds[i].events = POLLIN;
    }

    for (;;) {
        auto cur_ts=std::chrono::steady_clock::now();
        const int timeoutMS=log_send_ts > cur_ts ? (int)std::chrono::duration_cast<std::chrono::milliseconds>(log_send_ts - cur_ts).count() : 0;
        int rc = poll(fds, nfds,timeoutMS);

        if (rc < 0) {
            if (errno == EINTR || errno == EAGAIN) continue;
            throw std::runtime_error(StringFormat::convert("Poll error: %s", strerror(errno)));
        }

        cur_ts = std::chrono::steady_clock::now();

        if (cur_ts >= log_send_ts) {
            agg->dump_stats(stdout);
            log_send_ts = std::chrono::steady_clock::now() + log_interval;
        }

        if (rc == 0) continue; // timeout expired

        for (int i = 0; rc > 0 && i < nfds; i++) {
            if (fds[i].revents & (POLLERR | POLLNVAL)) {
                throw std::runtime_error("socket error!");
            }
            if (fds[i].revents & POLLIN) {
                rx[i]->loop_iter();
                rc -= 1;
            }
        }
    }
}


int main(int argc, char *const *argv) {
    TestFEC::test(4,8,1);
    TestFEC::test(4,8,1000);
    TestFEC::test2(4,8,100);

    int opt;
    uint8_t k = 8, n = 12, radio_port = 1;
    std::chrono::milliseconds log_interval{1000};
    int client_port = 5600;
    int srv_port = 0;
    std::string client_addr = "127.0.0.1";
    rx_mode_t rx_mode = LOCAL;
    std::string keypair = "gs.key";

    while ((opt = getopt(argc, argv, "K:fa:k:n:c:u:p:l:")) != -1) {
        switch (opt) {
            case 'K':
                keypair = optarg;
                break;
            case 'f':
                rx_mode = FORWARDER;
                break;
            case 'a':
                rx_mode = AGGREGATOR;
                srv_port = atoi(optarg);
                break;
            case 'k':
                k = atoi(optarg);
                break;
            case 'n':
                n = atoi(optarg);
                break;
            case 'c':
                client_addr = std::string(optarg);
                break;
            case 'u':
                client_port = atoi(optarg);
                break;
            case 'p':
                radio_port = atoi(optarg);
                break;
            case 'l':
                log_interval = std::chrono::milliseconds(atoi(optarg));
                break;
            default: /* '?' */
            show_usage:
                fprintf(stderr,
                        "Local receiver: %s [-K rx_key] [-k RS_K] [-n RS_N] [-c client_addr] [-u client_port] [-p radio_port] [-l log_interval] interface1 [interface2] ...\n",
                        argv[0]);
                fprintf(stderr,
                        "Remote (forwarder): %s -f [-c client_addr] [-u client_port] [-p radio_port] interface1 [interface2] ...\n",
                        argv[0]);
                fprintf(stderr,
                        "Remote (aggregator): %s -a server_port [-K rx_key] [-k RS_K] [-n RS_N] [-c client_addr] [-u client_port] [-l log_interval]\n",
                        argv[0]);
                fprintf(stderr, "Default: K='%s', k=%d, n=%d, connect=%s:%d, radio_port=%d, log_interval=%d\n",
                        keypair.c_str(), k, n, client_addr.c_str(), client_port, radio_port, (int)std::chrono::duration_cast<std::chrono::milliseconds>(log_interval).count());
                fprintf(stderr, "WFB version "
                WFB_VERSION
                "\n");
                exit(1);
        }
    }

    try {
        assert(rx_mode==LOCAL);
        std::shared_ptr<Aggregator> agg=std::make_shared<Aggregator>(client_addr, client_port, k, n, keypair);
        radio_loop(argc, argv, optind, radio_port, agg, log_interval);

    } catch (std::runtime_error &e) {
        fprintf(stderr, "Error: %s\n", e.what());
        exit(1);
    }
    return 0;
}
