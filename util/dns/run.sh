#!/bin/bash

set -x
set -e

node_name="sender5_to_cn"

date=$(date +%F_%H-%M-%S)

# cd into the dir of this script
cd "$(dirname "$0")" || exit

sudo pkill tcpdump || true

mkdir -p pcap && sudo chmod 777 pcap
mkdir -p data && sudo chmod 777 data


# TODO: need to specify hosts with 'or'
# capture DNS replies
sudo tcpdump -nn src port 53 and udp and not icmp -Uw "pcap/${node_name}_${date}.pcap" -Z root &

# wait for tcpdump to start
sleep 5

## find -L uniq -name "*.txt.uniq" -exec ./dnscensor -dip "$blackhole_ip" {} +
## The command above does not work in crontab (but works if executed manually). We thus use the following workaround:
#find -L uniq -name "*.txt.uniq" -exec cat {} + | ./dnscensor
cat - | ./dnscensor "$@"

# wait until all response come
sleep 5

sudo pkill tcpdump
