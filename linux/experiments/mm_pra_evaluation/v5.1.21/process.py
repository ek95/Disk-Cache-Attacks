#!/usr/bin/env python3
import os
import sys
import re
import pdb
import numpy
import operator
import argparse 


UNKNOWN_FILE = "!Unknown!"
MINOR_BITS = 20


def update_progressbar(i):
    sys.stdout.write('\r')
    sys.stdout.write("Processing [%-20s]" % ('=' * i))
    sys.stdout.flush()

# config command line parsing
parser = argparse.ArgumentParser(description="Processes the collected data from the mm_pra_evaluation collect script.")
parser.add_argument("input_file", type=str, help="generated perf trace file from the mm_pra_evaluation collect script")
parser.add_argument("target_obj", type=str, help="path to the target obj")
parser.add_argument("target_page", type=int, help="page offset of the targeted page")
parser.add_argument("output_file", type=str, help="output file with processed information")
args = parser.parse_args()

# get target file absolut path
target_obj_abs = os.path.abspath(args.target_obj)

# open input file 
trace_file = open(args.input_file, "r", errors='ignore')
trace_file_size = os.path.getsize(args.input_file)

processed_bytes = 0
old_process = -1
collect_page_info = False
target_page_evicted = False
shrink_inactive_list = False
eviction_runs_page_infos = []
eviction_runs_statistics = {"pc_evictions_before_target": [], "pc_evictions_after_target": []}
file_heatmap = {}
eviction_runs_file_heatmap = []
evicted_page_infos = []
tid_open_return = {}
# cache inode file mappings to speed up process
inode_file_cache = {}
# cache minor, major number to udev name to speed up process
minor_major_udev_name_cache = {}
# go through file line by line
line = trace_file.readline()
while line != "":
    process = round(processed_bytes / trace_file_size * 20)
    if process > old_process:
        update_progressbar(process)
    processed_bytes += len(line)
    old_process = process

    # stop collecting information after evictTargetPage returned
    if line.find("probe_ev_chk:evictTargetPage__return") != -1:
        collect_page_info = False
        eviction_runs_page_infos.append(evicted_page_infos)
        eviction_runs_file_heatmap.append(file_heatmap)
        line = trace_file.readline()
        continue
    # start of evictTargetPage function
    # start collecting information about pages evicted by the mm
    elif line.find("probe_ev_chk:evictTargetPage") != -1:
        collect_page_info = True
        target_page_evicted = False
        eviction_runs_statistics["pc_evictions_before_target"].append(0)
        eviction_runs_statistics["pc_evictions_after_target"].append(0)
        page_infos = []
        file_heatmap = {}
        line = trace_file.readline()
        continue

    # if we are currently not evicting do not collect data and read next line
    if not collect_page_info:
        line = trace_file.readline()
        continue

    # collect info about evicted page
    m1 = re.search(r".*\s+([0-9]+)\s+([0-9\.]+):.*probe:__delete_from_page_cache.*device=(0x[0-9a-zA-Z]+)\s+inode=(0x[0-9a-zA-Z]+)\s+page_offset=(0x[0-9a-zA-Z]+)\s+filename_short=(.*)", line)
    if m1 is not None:
        # parse regex groups + save information
        tid = int(m1.group(1)), 
        time = float(m1.group(2))
        device_nr = int(m1.group(3), 16)
        inode_hex_string = m1.group(4)
        page_offset = int(m1.group(5), 16)
        filename_short = m1.group(6)

        # search if shrink_inactive_list is in stack trace
        # (page cache delete was triggered by linux mm)
        shrink_inactive_list = False
        line = trace_file.readline()
        while line != "\n" and line != "":
            if line.find("shrink_inactive_list") != -1:
                shrink_inactive_list = True 
                break 
            line = trace_file.readline()
        # forward to next trace block  
        while line != "\n" and line != "": line = trace_file.readline() 
        # if shrink active list was not active continue 
        if not shrink_inactive_list:
            line = trace_file.readline()
            continue
        
        # else add page information to statistics 
        # lookup in cache
        if inode_hex_string in inode_file_cache:
            file = inode_file_cache[inode_hex_string]
        else:
            # reverse block device major, minor number to udev name
            if device_nr in minor_major_udev_name_cache:
                udev_name = minor_major_udev_name_cache[device_nr]
            else:
                # <linux/kdev_t.h> (https://elixir.bootlin.com/linux/v5.1.21/source/include/linux/kdev_t.h)
                major = device_nr >> MINOR_BITS
                minor = device_nr & ((1 << MINOR_BITS) - 1)
                udev_name = os.popen("udevadm info -rq name /sys/dev/block/" + str(major) + ":" + str(minor) + " 2>/dev/null").read().rstrip()
                minor_major_udev_name_cache[device_nr] = udev_name
                pdb.set_trace()

            # reverse inode to file
            output = os.popen("debugfs -R 'ncheck " + inode_hex_string + "' " + udev_name + " 2>/dev/null").read()
            output_lines = output.split("\n")
            if len(output_lines) < 3:
                file = UNKNOWN_FILE
            else:
                file = output_lines[1].split("\t")[1]

            # populate cache for fast filename retrieval
            # check if file part corresponds to short filename 
            # (consistency check, else return !Unknown!)
            if filename_short != "" and not (filename_short in file.split("/")[-1]):
                file = UNKNOWN_FILE
            inode_file_cache[inode_hex_string] = file
    
        evicted_page_info = {   
                                "file": file, 
                                "filename_short": filename_short, 
                                "page_offset": page_offset, 
                                "tid": tid, 
                                "time": time
                            }
        evicted_page_infos.append(evicted_page_info)

        # check if target page was evicted
        if evicted_page_info["file"] == target_obj_abs and evicted_page_info["page_offset"] == args.target_page:
            target_page_evicted= True
        # collect information about evictions
        elif not target_page_evicted:
            eviction_runs_statistics["pc_evictions_before_target"][-1] += 1
        else:
            eviction_runs_statistics["pc_evictions_after_target"][-1] += 1

        # file heatmap
        if evicted_page_info["file"] not in file_heatmap:
            file_heatmap[evicted_page_info["file"]] = 1
        else:
            file_heatmap[evicted_page_info["file"]] += 1

    line = trace_file.readline()
    


print("\n")

# show parsed information
for r in range(len(eviction_runs_statistics["pc_evictions_before_target"])):
    # Page eviction statistic
    pc_evictions_before_target = eviction_runs_statistics["pc_evictions_before_target"][r]
    pc_evictions_after_target = eviction_runs_statistics["pc_evictions_after_target"][r]
    print("Run %d" % r)
    print("--------------------------------------------------------------------------------")
    print("Page evictions before target: %d (%d MiB)" % (pc_evictions_before_target, pc_evictions_before_target * 4096 / 1024 / 1024))
    print("Page evictions affter target: %d (%d MiB)" % (pc_evictions_after_target, pc_evictions_after_target * 4096 / 1024 / 1024))
    print("--------------------------------------------------------------------------------")
    # File heatmap
    sorted_file_heatmap = dict(sorted(file_heatmap.items(), key=operator.itemgetter(1), reverse=True))
    for file in sorted_file_heatmap:
        print("%s: %d" % (file, file_heatmap[file]))
    print("--------------------------------------------------------------------------------")



print("Runs")
mean_pc_evictions_before_target = numpy.mean(eviction_runs_statistics["pc_evictions_before_target"])
std_pc_evictions_before_target = numpy.sqrt(numpy.var(eviction_runs_statistics["pc_evictions_before_target"]))
mean_pc_evictions_after_target = numpy.mean(eviction_runs_statistics["pc_evictions_after_target"])
std_pc_evictions_after_target = numpy.sqrt(numpy.var(eviction_runs_statistics["pc_evictions_after_target"]))

print("Page evictions before target:")
print("mean=%d (%d MiB) std=%d (%d MiB)" % (mean_pc_evictions_before_target, 
                                            mean_pc_evictions_before_target * 4096 / 1024 / 1024, 
                                            std_pc_evictions_before_target, 
                                            std_pc_evictions_before_target * 4096 / 1024 / 1024))
print("Page evictions after target:")
print("mean=%d (%d MiB) std=%d (%d MiB)" % (mean_pc_evictions_after_target, 
                                            mean_pc_evictions_after_target * 4096 / 1024 / 1024, 
                                            std_pc_evictions_after_target, 
                                            std_pc_evictions_after_target * 4096 / 1024 / 1024))

# create output file
out_file = open(args.output_file, "w")
# save as csv
for eviction_nr in range(len(eviction_runs_page_infos)):
    out_file.write("Eviction\t%d\n" % eviction_nr)
    out_file.write("Filename\tPage Offset\tTimestamp\n")
    for evicted_page_nr in range(len(eviction_runs_page_infos[eviction_nr])):
        page_info = eviction_runs_page_infos[eviction_nr][evicted_page_nr]
        out_file.write("%s\t%d\t%f\n" % (page_info["file"], page_info["page_offset"], page_info["time"]))
    out_file.write("\n")

print("Done")