#!/bin/bash

####
#### WARNING!!!
#### This script is depricated and **not supported** by author!
#### I leave it only for reference for **developers**.
#### Use python services instead.
####


WLAN=$1

BAND="5G"
#BAND="2G"

CHANNEL2G="6"
CHANNEL5G="149"

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

FEC_K=4
FEC_N=8

./wfb_tx -k $FEC_K -n $FEC_N -u 5600 -p 60 -M 4 -B 40 -f 2 $WLAN &

# $WFB_FOLDER/wfb_rx -c 127.0.0.1 -u 6100 -p 60 -K $WFB_FOLDER/gs.key -f 10 $MY_RX

# Video TX
# ./wfb_tx -p 1 -u 5600 -K drone.key $WLAN