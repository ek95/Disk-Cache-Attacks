#!/bin/bash

EV_CHK_DIR_REL="../../../../../evict_and_check/bin"
EV_CHK_BINARY="ev_chk"
EV_CHK_EVICT_FN_NAME="evictTargets__"
EV_CHK_PATH=$EV_CHK_DIR_REL/$EV_CHK_BINARY
TARGET_BINARY=$(realpath "./test.so")
TARGET_OFFSET=1
RAW_TRACE_FILE="raw_trace.txt"
TRACE_FILE="trace.csv"
DATA_PROCESSING_SCRIPT="./process.py"

#set -e

# delete perf probes (if existing)
#-------------------------------------------------------------------------------
perf probe -d "__delete_from_page_cache" || true 
perf probe -d "${EV_CHK_EVICT_FN_NAME}" || true 
perf probe -d "${EV_CHK_EVICT_FN_NAME}__return" || true

# set up perf probes
#-------------------------------------------------------------------------------
# trace beginning of shrink_page_list->__remove_mapping->__delete_from_page_cache and collect information about the evicted page
perf probe -a "__delete_from_page_cache device=page->mapping->host->i_sb->s_dev inode=page->mapping->host->i_ino page_offset=page->index"
# trace start of evictTargetPage function in ev_chk binary
perf probe -x $EV_CHK_PATH "${EV_CHK_EVICT_FN_NAME}"
# trace stop of evictTargetPage function in ev_chk binary
perf probe -x $EV_CHK_PATH "${EV_CHK_EVICT_FN_NAME}%return"

# set up limit frequency for collecting data
echo 100000 > sudo tee /proc/sys/kernel/perf_event_max_sample_rate

# run ev_chk and sample events
# -g record stack trace
# -m record buffer size
# -e event to record
# -a on all cores
# -p PID can be used to limit to pid
printf "${TARGET_BINARY}\n${TARGET_OFFSET} 0\n\n" > "${EV_CHK_DIR_REL}/eval.conf"
perf record -g -m 16M -e probe:__delete_from_page_cache -e probe_ev_chk:${EV_CHK_EVICT_FN_NAME} -e probe_ev_chk:${EV_CHK_EVICT_FN_NAME}__return -a bash -c "cd $EV_CHK_DIR_REL;./$EV_CHK_BINARY eval.conf | tee ev_chk.log" 

# convert collected data to log file
perf script -F comm,tid,time,event,trace,ip,sym > $RAW_TRACE_FILE

# run python to extract wanted data
$DATA_PROCESSING_SCRIPT $RAW_TRACE_FILE $TARGET_BINARY $TARGET_OFFSET $TRACE_FILE