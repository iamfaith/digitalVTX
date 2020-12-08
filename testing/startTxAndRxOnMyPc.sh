#!/bin/bash
# Given a PC with 2 wifi cards connected that support monitor mode,
# This starts the tx on one of them and the rx on the other one

MY_TX="wlxc4e984126183"
MY_RX="wlxc4e9840e3cbe"
WFB_FOLDER="/home/consti10/Desktop/wifibroadcast"

sudo rfkill unblock wifi
#sudo killall ifplugd #stop management of interface

sudo ifconfig $MY_TX down
sudo iw dev $MY_TX set monitor otherbss fcsfail
sudo ifconfig $MY_TX up
sudo iwconfig $MY_TX channel 13

sudo ifconfig $MY_RX down
sudo iw dev $MY_RX set monitor otherbss fcsfail
sudo ifconfig $MY_RX up
sudo iwconfig $MY_RX channel 13

gnome-terminal -- $WFB_FOLDER/wfb_tx -k 4 -n 8 -u 6000 -p 60 -K $WFB_FOLDER/drone.key $MY_TX

$WFB_FOLDER/wfb_rx -k 4 -n 8 -c 127.0.0.1 -u 6100 -p 60 -K $WFB_FOLDER/gs.key $MY_RX

#other usefull commands:
#sudo iw dev
#nc -u localhost 6000
#nc -u -l localhost 6100
