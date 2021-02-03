raspivid -n  -ex fixedfps -w 960 -h 540 -b 4000000 -fps 30 -vf -hf -t 0 -o - | \
               gst-launch-1.0 -v fdsrc ! h264parse ! rtph264pay config-interval=1 pt=35 ! udpsink sync=false host=127.0.0.1  port=5600


