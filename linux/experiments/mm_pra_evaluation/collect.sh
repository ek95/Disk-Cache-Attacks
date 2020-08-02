#!/bin/bash

EV_CHK_BINARY=../../evict_and_check/build/bin/ev_chk
TARGET_BINARY=../../evict_and_check/build/bin/test.so
TARGET_OFFSET=1
DATA_PROCESSING_SCRIPT=process.py

# delete perf probes (if existing)
#-------------------------------------------------------------------------------
perf probe -d "try_to_unmap"
perf probe -d "try_to_unmap__return"
perf probe -d "evictTargetPage"
perf probe -d "evictTargetPage__return"

# set up perf probes
#-------------------------------------------------------------------------------
# trace beginning of try_to_unmap and collect information about page
perf probe 'try_to_unmap page->index page->mapping->host->i_ino'
# trace end  of try_to_unmap and collect return value
perf probe 'try_to_unmap%return $retval'
# trace start of evictTargetPage function in ev_chk binary
perf probe -x $EV_CHK_BINARY 'evictTargetPage'
# trace stop of evictTargetPage function in ev_chk binary
perf probe -x $EV_CHK_BINARY 'evictTargetPage%return'

# set up limit frequency for collecting data
echo 100000 > sudo tee /proc/sys/kernel/perf_event_max_sample_rate

# run ev_chk and sample events
# -p PID can be used to limit to pid
perf record -m 16M -e probe:try_to_unmap -e probe:try_to_unmap__return -e probe_ev_chk:evictTargetPage -e probe_ev_chk:evictTargetPage__return -a $EV_CHK_BINARY $TARGET_BINARY $TARGET_OFFSET

# convert collected data to log file
perf script -F comm,tid,time,event,trace > log.txt

# run python to extract wanted data
python3 $DATA_PROCESSING_SCRIPT log.txt out.csv "\$TARGET_BINARY" $TARGET_OFFSET
