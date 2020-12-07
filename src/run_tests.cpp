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


int main(int argc, char *const *argv){
    std::cout<<"Tests for Wifibroadcast\n";
    try {
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
    }catch (std::runtime_error &e) {
        fprintf(stderr, "Error: %s\n", e.what());
        exit(1);
    }
    std::cout<<"Tests Passing\n";
    return 0;
}