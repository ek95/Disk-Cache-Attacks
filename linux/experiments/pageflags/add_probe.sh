#!/bin/bash


# delete perf probes (if existing)
#-------------------------------------------------------------------------------
perf probe -d "handle_mm_fault"

# set up perf probes
#-------------------------------------------------------------------------------
# trace beginning of a mm fault to check if access to invactive list faults
perf probe 'handle_mm_fault'

