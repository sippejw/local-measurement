#!/bin/bash

cd "$(dirname "$0")" || exit

date=$(date +%F_%H-%M-%S)

# set max open file to a large number
ulimit -n 50000

DST_NAME="shanghai7"
DST_IP="1.1.1.1"
MIN_DSTPORT=10000
MAX_DSTPORT=65000

INPUT_FILE='alexa-top1m-2019-04-26_0900_UTC.txt'
OUTPUT_FILE="1m_sni_censorship_${DST_NAME}_${date}.csv"

cat "$INPUT_FILE" | ./sincensor -dip "$DST_IP" -p 10000-65000 -timeout 6s -worker 200 -out "$OUTPUT_FILE"
