//
// Created by consti10 on 06.12.20.
//

#ifndef WIFIBROADCAST_OPENHDSTATISTICSWRITER_H
#define WIFIBROADCAST_OPENHDSTATISTICSWRITER_H

#include <stdint.h>

// TODO what happens here has to be decided yet
//

class OpenHDStatisticsWriter{
public:
    // @param multiplexIdx: the unique stream id, also called radio_port
    void writeStats(uint8_t multiplexIdx){
        // TODO write to udp port or shared memory or ...
    }
};

#endif //WIFIBROADCAST_OPENHDSTATISTICSWRITER_H
