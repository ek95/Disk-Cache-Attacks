#!/usr/bin/env python3
import os
import sys
import re
import pdb
import numpy
import operator


TARGET_PARTITION = "/dev/nvme0n1p2"


def update_progressbar(i):
    sys.stdout.write('\r')
    sys.stdout.write("Processing [%-20s]" % ('=' * i))
    sys.stdout.flush()


if len(sys.argv) != 5:
    print("USAGE %s <log file> <output csv file> <target shared obj> <target page offset>" % sys.argv[0])
    exit(-1)

# create output file
out_file = open(sys.argv[2], "w")

# get line numbers
line_count = num_lines = sum(1 for line in open(sys.argv[1]))

log_file = open(sys.argv[1], "r")
line_nr = 0
collect_page_info = False
target_page_evicted = False
shrink_inactive_list = False
eviction_runs_page_infos = []
eviction_runs_statistics = {"pc_evictions_before_target": []}
file_heatmap = {}
eviction_runs_file_heatmap = []
page_infos = []
tid_open_return = {}
inode_filename_cache = {}
# go through file line by line
for line in log_file:
    #update_progressbar(round(line_nr / line_count * 20))
    line_nr += 1

    # stop collecting information after evictTargetPage returned
    if line.find("evictTargetPage__return") != -1:
        collect_page_info = False
        eviction_runs_page_infos.append(page_infos)
        eviction_runs_file_heatmap.append(file_heatmap)
        continue
    # start of evictTargetPage function
    # start collecting information about pages unmapped by the mm
    elif line.find("evictTargetPage") != -1:
        collect_page_info = True
        page_infos = []
        target_page_unmapped = False
        eviction_runs_statistics["pc_evictions_before_target"].append(0)
        file_heatmap = {}
        continue

    if not collect_page_info:
        continue

    # check if shrink_inactive_list is in stack trace
    if line.find("shrink_inactive_list") != -1:
        shrink_inactive_list = True

    # collect info about evicted page
    m1 = re.search(".*\s+([0-9]+)\s+([0-9\.]+):.*__delete_from_page_cache.*page_offset=(0x[0-9a-zA-Z]+)\s+inode=(0x[0-9a-zA-Z]+)\s+filename_short=(.*)", line)
    if m1 is not None:
        inode_hex_string = m1.group(4)
        # lookup in cache
        if inode_hex_string in inode_filename_cache:
            filename = inode_filename_cache[inode_hex_string]
        else:
            # reverse inode to file
            output = os.popen("debugfs -R 'ncheck " + inode_hex_string + "' " + TARGET_PARTITION + " 2>/dev/null").read()
            output_lines = output.split("\n")
            if len(output_lines) < 3:
                filename = "!Unknown!"
            else:
                filename = output_lines[1].split("\t")[1]
            # get short filename 
            short_filename = m1.group(5)
            # populate cache for fast filename retrieval
            # check if file part corresponds to filename 
            if filename.split("/")[-1] != short_filename:
                filename = "!Unknown!"
            inode_filename_cache[inode_hex_string] = filename
    
        page_infos.append({"filename": filename, "short_filename": short_filename, "page_offset": int(m1.group(3), 16), "tid": int(m1.group(1)), "time": float(m1.group(2))})
        continue

        # check if target page was evicted
        if page_info["file"] == sys.argv[3] and page_info["page_offset"] == int(sys.argv[4]):
            target_page_evicted= True
        # collect statistics if target page is not unmapped
        if not target_page_evicted:
            eviction_runs_statistics["evictions_before_target"][-1] += 1
            # file heatmap
            if page_info["file"] not in file_heatmap:
                file_heatmap[page_info["file"]] = 1
            else:
                file_heatmap[page_info["file"]] += 1
        continue

print("\n")

# show parsed information
for r in range(len(eviction_runs_statistics["evictions_before_target"])):
    # Page eviction statistic
    eviction_tries = eviction_runs_statistics["eviction_tries_before_target"][r]
    evictions = eviction_runs_statistics["evictions_before_target"][r]
    print("Run %d" % r)
    print("--------------------------------------------------------------------------------")
    print("Page eviction tries before target: %d (%d MiB)" % (eviction_tries, eviction_tries * 4096 / 1024 / 1024))
    print("Page evictions before target: %d (%d MiB)" % (evictions, evictions * 4096 / 1024 / 1024))
    print("--------------------------------------------------------------------------------")
    # File heatmap
    sorted_file_heatmap = dict(sorted(file_heatmap.items(), key=operator.itemgetter(1), reverse=True))
    for file in sorted_file_heatmap:
        print("%s: %d" % (file, file_heatmap[file]))
    print("--------------------------------------------------------------------------------")



print("Runs")
mean_eviction_tries = numpy.mean(eviction_runs_statistics["eviction_tries_before_target"])
std_eviction_tries = numpy.sqrt(numpy.var(eviction_runs_statistics["eviction_tries_before_target"]))
mean_evictions = numpy.mean(eviction_runs_statistics["evictions_before_target"])
std_evictions = numpy.sqrt(numpy.var(eviction_runs_statistics["evictions_before_target"]))

print("Page eviction tries before target:")
print("mean=%d (%d MiB) std=%d (%d MiB)" % (mean_eviction_tries, mean_eviction_tries * 4096 / 1024 / 1024, std_eviction_tries, std_eviction_tries * 4096 / 1024 / 1024))
print("Page evictions before target:")
print("mean=%d (%d MiB) std=%d (%d MiB)" % (mean_evictions, mean_evictions * 4096 / 1024 / 1024, std_evictions, std_evictions * 4096 / 1024 / 1024))

# save as csv
for eviction_nr in range(len(eviction_runs_page_infos)):
    out_file.write("Eviction\t%d\n" % eviction_nr)
    out_file.write("Filename\tPage Offset\tUnmapped\tRuntime try_to_unmap\n")
    for unmapped_page_nr in range(len(eviction_runs_page_infos[eviction_nr])):
        page_info = eviction_runs_page_infos[eviction_nr][unmapped_page_nr]
        out_file.write("%s\t%d\t%d\t%f\n" % (page_info["file"], page_info["page_offset"], page_info["unmapped"], page_info["time_try_to_unmap"]))
    out_file.write("\n")

print("Done")
