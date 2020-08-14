#!/bin/bash

EV_CHK_DIR_REL="../../../evict_and_check/build/bin"
EV_CHK_BINARY="ev_chk"
EV_CHK_PATH=$EV_CHK_DIR_REL/$EV_CHK_BINARY
TARGET_BINARY="test.so"
TARGET_OFFSET=1
RAW_TRACE_FILE="raw_trace.txt"
TRACE_FILE="trace.csv"
DATA_PROCESSING_SCRIPT="./process.py"

# delete perf probes (if existing)
#-------------------------------------------------------------------------------
perf probe -d "__delete_from_page_cache"
perf probe -d "evictTargetPage"
perf probe -d "evictTargetPage__return"

# set up perf probes
#-------------------------------------------------------------------------------
# trace beginning of __delete_from_page_cache and collect information about the evicted page
perf probe "__delete_from_page_cache device=page->mapping->host->i_sb->s_dev inode=page->mapping->host->i_ino page_offset=page->index"
# trace start of evictTargetPage function in ev_chk binary
perf probe -x $EV_CHK_PATH "evictTargetPage"
# trace stop of evictTargetPage function in ev_chk binary
perf probe -x $EV_CHK_PATH "evictTargetPage%return"

# set up limit frequency for collecting data
echo 100000 > sudo tee /proc/sys/kernel/perf_event_max_sample_rate

# run ev_chk and sample events
# -g record stack trace
# -m record buffer size
# -e event to record
# -a on all cores
# -p PID can be used to limit to pid
perf record -g -m 16M -e probe:__delete_from_page_cache -e probe_ev_chk:evictTargetPage -e probe_ev_chk:evictTargetPage__return -a bash -c "cd $EV_CHK_DIR_REL;./$EV_CHK_BINARY $TARGET_BINARY $TARGET_OFFSET"

# convert collected data to log file
perf script -F comm,tid,time,event,trace,ip,sym > $RAW_TRACE_FILE

# run python to extract wanted data
$DATA_PROCESSING_SCRIPT $RAW_TRACE_FILE $TARGET_BINARY $TARGET_OFFSET $TRACE_FILE
