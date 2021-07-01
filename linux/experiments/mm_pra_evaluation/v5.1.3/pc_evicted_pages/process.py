#!/usr/bin/env python3
# NOTE: The inode-filename reverse mapping might not be correct if a inode content changed.
import os
import sys
import re
import pdb
import numpy
import operator
import argparse 

EV_CHK_EVICT_FN_NAME = "evictTargets_"
UNKNOWN_FILE = "!Unknown!"
MINOR_BITS = 20


def update_progressbar(i):
    sys.stdout.write('\r')
    sys.stdout.write("Processing [%-20s]" % ('=' * i))
    sys.stdout.flush()

# config command line parsing
parser = argparse.ArgumentParser(description="Processes the collected data from the mm_pra_evaluation collect script.")
parser.add_argument("input_file", type=str, help="generated perf trace file from the mm_pra_evaluation collect script")
parser.add_argument("target_obj", type=str, help="path to the target object")
parser.add_argument("target_page", type=int, help="offset in pages of the targeted page")
parser.add_argument("output_file", type=str, help="output file with the processed information")
args = parser.parse_args()

# get target file statistics
target_obj_stat = os.stat(args.target_obj)
target_obj_device_nr = target_obj_stat.st_dev
target_obj_major = os.major(target_obj_device_nr)
target_obj_minor = os.minor(target_obj_device_nr)
target_obj_inode = target_obj_stat.st_ino
target_obj_page_offset = args.target_page

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
# cache inode-file mappings to speed up process
device_inode_file_cache = {}
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

    # stop collecting information after evictTargets_ returned
    if line.find("probe_ev_chk:" + EV_CHK_EVICT_FN_NAME + "__return") != -1:
        collect_page_info = False
        eviction_runs_page_infos.append(evicted_page_infos)
        eviction_runs_file_heatmap.append(file_heatmap)
        line = trace_file.readline()
        continue
    # start of evictTargets_ function, collect information about pages evicted by the mm
    elif line.find("probe_ev_chk:" + EV_CHK_EVICT_FN_NAME) != -1:
        collect_page_info = True
        target_page_evicted = False
        eviction_runs_statistics["pc_evictions_before_target"].append(0)
        eviction_runs_statistics["pc_evictions_after_target"].append(0)
        evicted_page_infos = []
        file_heatmap = {}
        line = trace_file.readline()
        continue

    # if we are currently not evicting do not collect data and read next line
    if not collect_page_info:
        line = trace_file.readline()
        continue

    # collect infos about evicted page
    probe_match = re.search(r"([^\s]*)\s+([0-9]+)\s+([0-9\.]+):.*probe:__delete_from_page_cache.*"
                            r"device=(0x[0-9a-zA-Z]+)\s+inode=(0x[0-9a-zA-Z]+)\s+page_offset=(0x[0-9a-zA-Z]+).*", line)
    # probe matched
    if probe_match is not None:
        # parse regex groups + save information
        image_name = probe_match.group(1)
        tid = int(probe_match.group(2)), 
        time = float(probe_match.group(3))
        device_nr = int(probe_match.group(4), 16)
        inode_hex_string = probe_match.group(5)
        inode = int(inode_hex_string, 16)
        page_offset = int(probe_match.group(6), 16)

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
        # if shrink_inactive_list was not active, continue 
        if not shrink_inactive_list:
            line = trace_file.readline()
            continue
        
        # else add page information to statistics 
        if device_nr in device_inode_file_cache and inode in device_inode_file_cache[device_nr]:
            file = device_inode_file_cache[device_nr][inode]
        else:
            # reverse major, minor number of block device to udev name
            udev_name = None
            if device_nr in minor_major_udev_name_cache:
                udev_name = minor_major_udev_name_cache[device_nr]
            else:
                # <linux/kdev_t.h> (https://elixir.bootlin.com/linux/v5.1.21/source/include/linux/kdev_t.h)
                major = device_nr >> MINOR_BITS
                minor = device_nr & ((1 << MINOR_BITS) - 1)
                udevadm_p = os.popen("udevadm info -rq name /sys/dev/block/" + str(major) + ":" + str(minor) + 
                                     " 2> /dev/null")
                output = udevadm_p.read()
                returncode = udevadm_p.close()
                if returncode is None and len(output) > 0:
                    udev_name = output.rstrip()
                    minor_major_udev_name_cache[device_nr] = udev_name

            file = None
            tries = 0
            while udev_name is not None and file is None and tries < 5:
                # reverse inode to file (try max. 5 times)
                debugfs_p = os.popen("debugfs -R 'ncheck " + inode_hex_string + "' " + udev_name + " 2> /dev/null")
                output_lines = debugfs_p.read().split("\n")
                returncode = debugfs_p.close()
                if returncode is None and "Inode\tPathname" in output_lines[0] and len(output_lines) > 2:
                    file = output_lines[1].split("\t")[1]
                    # populate cache for fast filename retrieval
                    if device_nr not in device_inode_file_cache:
                        device_inode_file_cache[device_nr] = {}
                    device_inode_file_cache[device_nr][inode] = file
                tries += 1

        if file is None:
            print("Warning: Filename could not have been gathered:")
            print("Inode: " + str(inode_hex_string))
            print("Device number: " + str(device_nr))
            print("udev name: " + str(udev_name))
            print("")
    
        # collect data about evicted pages
        evicted_page_info = {   
                                "device_major": device_nr >> MINOR_BITS,
                                "device_minor": device_nr & ((1 << MINOR_BITS) - 1), 
                                "inode": inode,
                                "file": UNKNOWN_FILE if file is None else file, 
                                "page_offset": page_offset, 
                                "image_name": image_name,
                                "tid": tid, 
                                "time": time
                            }
        evicted_page_infos.append(evicted_page_info)

        # check if target page was evicted
        if(evicted_page_info["device_major"] == target_obj_major and 
           evicted_page_info["device_minor"] == target_obj_minor and
           evicted_page_info["inode"] == target_obj_inode and 
           evicted_page_info["page_offset"] == target_obj_page_offset):
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
    print("Page evictions before target: %d (%d MiB)" % (pc_evictions_before_target, pc_evictions_before_target * 
                                                         4096 / 1024 / 1024))
    print("Page evictions affter target: %d (%d MiB)" % (pc_evictions_after_target, pc_evictions_after_target * 
                                                         4096 / 1024 / 1024))
    print("--------------------------------------------------------------------------------")
    # File heatmap
    print("Evicted pages per unique file:")
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
    out_file.write("Run by\tFilename\tPage Offset\tTimestamp\n")
    for evicted_page_nr in range(len(eviction_runs_page_infos[eviction_nr])):
        page_info = eviction_runs_page_infos[eviction_nr][evicted_page_nr]
        out_file.write("%s\t%s\t%d\t%f\n" % (page_info["image_name"], page_info["file"], 
                                             page_info["page_offset"], page_info["time"]))
    out_file.write("\n")

print("Done")
