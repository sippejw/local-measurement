#!/bin/bash

set -x
set -e

blackhole_ip="1.1.1.1"

node_name="sender_sh"

date=$(date +%F_%H-%M-%S)

# cd into the dir of this script
cd "$(dirname "$0")" || exit

sudo pkill tcpdump || true

sleep 3

mkdir -p pcap
chmod 777 pcap

# capture DNS replies
sudo tcpdump -nn host "$blackhole_ip" and src port 53 and udp and not icmp -w "pcap/zone_routine_${node_name}_${date}.pcap" -Z root &

pid_tcpdump="$!"

echo "$pid_tcpdump" > pids_to_be_killed.txt

# wait for tcpdump to start
sleep 5

## find -L uniq -name "*.txt.uniq" -exec ./dnscensor -dip "$blackhole_ip" {} +
## The command above does not work in crontab (but works if executed manually). We thus use the following workaround:
find -L uniq -name "*.txt.uniq" -exec cat {} + | ./dnscensor -dip "$blackhole_ip"

# wait until all response come, yes we are that fast
sleep 5

sudo pkill tcpdump

#sudo cat pids_to_be_killed.txt | xargs sudo kill -9

#sudo kill -9 "$pid_tcpdump"

#sudo pkill tcpdump
