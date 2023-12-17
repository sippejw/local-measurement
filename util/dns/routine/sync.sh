#!/bin/bash

set -x
set -e

cd "$(dirname "$0")" || exit

go build ..

rsync -auvP ../routine sender5:~ &
rsync -auvP ../routine sender1:~ &

wait
