#!/bin/bash

EV_CHK_BINARY=../../evict_and_check/build/bin/ev_chk
TARGET_BINARY=../../evict_and_check/build/bin/test.so
TARGET_OFFSET=1
DATA_PROCESSING_SCRIPT=process.py

# delete perf probes (if existing)
#-------------------------------------------------------------------------------
perf probe -d "__delete_from_page_cache"
perf probe -d "evictTargetPage"
perf probe -d "evictTargetPage__return"

# set up perf probes
#-------------------------------------------------------------------------------
# trace beginning of __delete_from_page_cache and collect information about the evicted page
# %di is first argument, 
perf probe "__delete_from_page_cache page_offset=page->index inode=page->mapping->host->i_ino filename_short=-120(+312(+0(+24(%di)))):string"
# perf probe "__delete_from_page_cache page->index page->mapping->host->i_ino"
# page->mapping->host->i_dentry.first is a pointer to (struct dentry *)->d_alias
# we want to reach (struct dentry *)->d_iname so we calculate the neccessary 
# offset from (struct dentry *)->d_alias to (struct dentry *)->d_iname as: -120
# d_name=-120(+312(+0(+24(%di)))):string"
# trace start of evictTargetPage function in ev_chk binary
perf probe -x $EV_CHK_BINARY "evictTargetPage"
# trace stop of evictTargetPage function in ev_chk binary
perf probe -x $EV_CHK_BINARY "evictTargetPage%return"

# set up limit frequency for collecting data
echo 100000 > sudo tee /proc/sys/kernel/perf_event_max_sample_rate

# run ev_chk and sample events
# -p PID can be used to limit to pid
perf record -g -m 16M -e probe:__delete_from_page_cache -e probe_ev_chk:evictTargetPage -e probe_ev_chk:evictTargetPage__return -a $EV_CHK_BINARY $TARGET_BINARY $TARGET_OFFSET

# convert collected data to log file
perf script -F comm,tid,time,event,trace > log.txt

# run python to extract wanted data
python3 $DATA_PROCESSING_SCRIPT log.txt out.csv "\$TARGET_BINARY" $TARGET_OFFSET
