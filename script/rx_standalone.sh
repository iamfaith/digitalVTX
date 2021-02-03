#!/bin/bash

####
#### WARNING!!!
#### This script is depricated and **not supported** by author!
#### I leave it only for reference for **developers**.
#### Use python services instead.
####

WLANS=$@
BAND="5G"
#BAND="2G"

CHANNEL2G="6"
CHANNEL5G="149"

for WLAN in $WLANS
do
ifconfig $WLAN down
iw dev $WLAN set monitor otherbss
iw reg set BO
ifconfig $WLAN up

case $BAND in
  "5G")
      echo "Setting $WLAN to channel $CHANNEL5G"
      iw dev $WLAN set channel $CHANNEL5G HT40+
      ;;
  "2G")
      echo "Setting $WLAN to channel $CHANNEL2G"
      iw dev $WLAN set channel $CHANNEL2G HT40+
      ;;
   *)
      echo "Select 2G or 5G band"
      exit -1;
      ;;
esac
done

# No UI, video only
# ./wfb_rx -p 1 -u 5600 -K gs.key $WLANS
FEC_K=4
FEC_N=8

./wfb_rx -c 127.0.0.1 -u 5600 -p 60 -f 10 $WLANS