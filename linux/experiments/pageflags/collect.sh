#!/bin/bash

# ignore INT
trap '' INT   

# exit if argument not provided
if (($# != 1)) 
then 
	echo "USAGE: $0 <PID>"
	exit -1
fi

# delete perf probes (if existing)
#-------------------------------------------------------------------------------
perf probe -d "handle_mm_fault"

# set up perf probes
#-------------------------------------------------------------------------------
# trace beginning of a mm fault to check if access to invactive list faults
perf probe 'handle_mm_fault'

# data sampling, processing
#-------------------------------------------------------------------------------
# run and sample events
# -p PID can be used to limit to pid
perf record -m 16M  -e page-faults -e probe:handle_mm_fault -p $1

# print collected data to stdio
perf script -F comm,tid,time,event,trace
