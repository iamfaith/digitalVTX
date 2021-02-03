####  wifi

gst-launch-1.0 uvch264src device=/dev/video0 initial-bitrate=6000000 average-bitrate=6000000 iframe-period=1000 name=src auto-start=true \
               src.vidsrc ! queue ! video/x-h264,width=1920,height=1080,framerate=30/1 ! h264parse ! rtph264pay ! udpsink host=localhost port=5600
To encode a Raspberry Pi Camera V2:

raspivid -n  -ex fixedfps -w 960 -h 540 -b 4000000 -fps 30 -vf -hf -t 0 -o - | \
               gst-launch-1.0 -v fdsrc ! h264parse ! rtph264pay config-interval=1 pt=35 ! udpsink sync=false host=127.0.0.1 port=5600
To decode:

 gst-launch-1.0 udpsrc port=5600 caps='application/x-rtp, media=(string)video, clock-rate=(int)90000, encoding-name=(string)H264' \
               ! rtph264depay ! avdec_h264 ! clockoverlay valignment=bottom ! autovideosink fps-update-interval=1000 sync=false


# for PC  x264enc
gst-launch-1.0  filesrc location=a.mp4 ! decodebin ! videorate ! video/x-raw,framerate=30/1 ! videoscale ! video/x-raw,width=720,height=480 ! x264enc ! video/x-h264,framerate=30/1,profile=baseline ! rtph264pay ! udpsink host=127.0.0.1 port=5600



# for picar
# x264enc
gst-launch-1.0  filesrc location=a.mp4 ! decodebin ! videorate ! video/x-raw,framerate=30/1 ! videoscale ! video/x-raw,width=320,height=240 ! x264enc ! video/x-h264,framerate=30/1,profile=baseline ! rtph264pay ! udpsink host=192.168.31.226  port=5600

# omxh264enc
gst-launch-1.0  filesrc location=a.mp4 ! decodebin ! videorate ! video/x-raw,framerate=30/1 ! videoscale ! video/x-raw,width=720,height=480 ! omxh264enc ! video/x-h264,framerate=30/1,profile=high,target-bitrate=10000000  ! rtph264pay ! udpsink host=192.168.31.226  port=5600

# new.mp4
gst-launch-1.0  filesrc location=new.mp4 ! decodebin ! videorate ! video/x-raw,framerate=30/1 ! videoscale ! video/x-raw,width=320,height=240 ! omxh264enc ! video/x-h264,framerate=30/1,profile=baseline ! rtph264pay ! udpsink host=192.168.31.226  port=5600