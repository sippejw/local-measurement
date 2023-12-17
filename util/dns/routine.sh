#!/bin/bash

set -x
set -e

cd "$(dirname "$0")" || exit

while true; do
#    nice -20 ionice -c 2 -n 0 flock --nonblock dnscensor.lock find -L uniq -name "*.txt.uniq" -exec cat {} + | ./run.sh >/dev/null 2>&1
#    flock --nonblock dnscensor.lock find -L uniq -name "*.txt.uniq" -exec cat {} + | ./run.sh >/dev/null 2>&1
    find -L uniq -name "*.txt.uniq" -exec cat {} + | sudo docker run --rm -i -v "$PWD/data:/app/data" -v "$PWD/pcap:/app/pcap" user/dnscensor
    sleep 60
done
