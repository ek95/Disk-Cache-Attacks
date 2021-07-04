#!/bin/bash

EV_CHK_BINARY="ev_chk"
ACCESS_PATH="../../../../../tools/access/bin/access"
TARGET_PATH="./test.so"
TARGET_OFFSET=1
ACCESS_PERIOD_MS=1000
ACCESS_COUNT=1

set -e

if [ ! -f "$TARGET_PATH" ]; then
    dd if="/dev/urandom" of="./$TARGET_PATH" bs=4096 count=20
fi

${ACCESS_PATH} ${TARGET_PATH} ${TARGET_OFFSET} $ACCESS_PERIOD_MS $ACCESS_COUNT
sleep 15
killall $EV_CHK_BINARY
