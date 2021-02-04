export rx="wlx70f11c507eb2" 

ifconfig $rx down
iw dev $rx set monitor otherbss fcsfail
ifconfig $rx up

iwconfig $rx channel 6

./wfb_rx -c 10.0.2.15 -p 3 -u 5600 -K gs.key $rx