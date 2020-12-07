//
// Created by consti10 on 06.12.20.
//

#ifndef WIFIBROADCAST_OPENHDSTATISTICSWRITER_H
#define WIFIBROADCAST_OPENHDSTATISTICSWRITER_H

#include <stdint.h>

// TODO what happens here has to be decided yet
// write the fec decoding stats (and optionally RSSI ) for each rx stream

class OpenHDStatisticsWriter{
public:
    struct Data{
        // all these values are absolute (like done previously in OpenHD)
        uint64_t count_p_all=0;
        uint64_t count_p_bad=0;
        uint64_t count_p_dec_err=0;
        uint64_t count_p_dec_ok=0;
        uint64_t count_p_fec_recovered=0;
        uint64_t count_p_lost=0;
        // TODO the rssi stuff ( a bit complicated)
        // since multiple RX are listening on the same wifi card
    };
    // @param multiplexIdx: the unique stream id, also called radio_port
    void writeStats(const uint8_t RADIO_PORT,const Data& data){
        // Perhaps RADIO_PORT==0 means video and so on
        // TODO write to udp port or shared memory or ...
    }
};

#endif //WIFIBROADCAST_OPENHDSTATISTICSWRITER_H
