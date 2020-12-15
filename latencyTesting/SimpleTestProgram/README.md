Compile code:
Just run make 

Collection of commands:
git add . && git commit -m "X" && git push
git reset --hard && git pull

Receive via udp and write to file
nc -u -l 5060 > newfile.txt

Send file via udp
cat newfile.txt | nc -u localhost 5060
// Loop data back via ethernet without wifibroadcast
nc -u -l 6002 | nc -u "192.168.0.13" 6001

// to forward via svpcom run my_wb_tx and my_wb_rx


// make executable
chmod u+x my_wfb_rx.sh && chmod u+x my_wfb_tx.sh 


// perf commands
/usr/local/bin/perf-4.19.122-v7+ sched record -a sleep 8
/usr/local/bin/perf-4.19.122-v7+ sched latency -s max



