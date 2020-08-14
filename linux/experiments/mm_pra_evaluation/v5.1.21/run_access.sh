#!/bin/bash

EV_CHK_BINARY="ev_chk"
ACCESS_PATH="../../../tools/access/bin/access"
TARGET_PATH="../../../evict_and_check/build/bin/test.so"
TARGET_OFFSET=1
ACCESS_PERIOD_MS=1000
ACCESS_COUNT=10

${ACCESS_PATH} ${TARGET_PATH} ${TARGET_OFFSET} $ACCESS_PERIOD_MS $ACCESS_COUNT
killall $EV_CHK_BINARY