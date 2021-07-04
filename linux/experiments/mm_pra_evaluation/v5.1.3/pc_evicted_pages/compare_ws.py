#!/usr/bin/env python3.8

import sys 
import csv
import pdb

# open file 
profiled_ws_file = open(sys.argv[1], "r")
evicted_pages_file = open(sys.argv[2], "r")

# parse profiled file
profiled_ws = {}
while True:
    file_line = profiled_ws_file.readline()
    file_line = file_line.rstrip("\n")
    if len(file_line) == 0:
        break
    profiled_ws[file_line] = set()
    while True:
        sequence_line = profiled_ws_file.readline()
        sequence_line = sequence_line.rstrip("\n")
        if len(sequence_line) == 0:
            break
        sequence_tokens = sequence_line.split("-")
        sequence = [int(sequence_tokens[0]), int(sequence_tokens[1])]
        for page in range(sequence[0], sequence[1] + 1):
            profiled_ws[file_line].add(page)

# skip header line
evicted_pages_file.readline()
evicted_pages_file.readline()
evicted_pages_csv = csv.reader(evicted_pages_file, delimiter='\t')
# check how many of the evicted pages were not in the working set
evicted_pages_in_ws = 0
evicted_pages_not_in_ws = 0
evicted_pages_not_in_ws_wo_unknown = 0
evicted_pages = 0
for row in evicted_pages_csv:
    if len(row) == 0:
        break

    if row[1] in profiled_ws and int(row[2]) in profiled_ws[row[1]]:
        evicted_pages_in_ws += 1    
    else:
        if row[1] != "!Unknown!":
            evicted_pages_not_in_ws_wo_unknown += 1
        evicted_pages_not_in_ws += 1
    evicted_pages += 1

print("Evicted file pages that were in working set: {}".format(evicted_pages_in_ws))
print("\t in percent of total evicted pages: {}%".format(evicted_pages_in_ws / evicted_pages * 100))
print("Evicted file pages that were not in working set: {}".format(evicted_pages_not_in_ws))
print("\t in percent of total evicted pages: {}%".format(evicted_pages_not_in_ws / evicted_pages * 100))
print("Evicted file pages that were not in working set (without unknown files): {}".format(evicted_pages_not_in_ws_wo_unknown))
print("\t in percent of total evicted pages: {}%".format(evicted_pages_not_in_ws_wo_unknown / evicted_pages * 100))