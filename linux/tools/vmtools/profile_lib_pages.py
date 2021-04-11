#!/usr/bin/env python3
# NOTE only works as long as system is not thrashing memory
# (exermined pages have to stay in memory)
import argparse 
import vmtools
import mmap
import time
import tqdm
import matplotlib
import matplotlib.pyplot as plt
import numpy as np
import os
import json


def argmax(iterable):
    if len(iterable) == 0:
        return (None, None)

    current_max = iterable[0] 
    current_max_i = 0
    for i in range(len(iterable)):
        x = iterable[i]
        if x > current_max:
            current_max = x 
            current_max_i = i

    return (current_max, current_max_i)

def createEventPageHitHeatmap(file_path, file_offset, hit_data_raw, max_val, 
                              pages_per_row = 16, show = True, save = False):
    # remove negative numbers + scale
    data = [x if x >= 0 else 0 for x in hit_data_raw]
    # reorganize data  
    data = [data[i : i + pages_per_row] for i  in range(0, len(data), pages_per_row)]
    if len(data) > 1 and len(data[-1]) < pages_per_row:
        data[-1] += [0] * (pages_per_row - len(data[-1]))
    # generate x labels
    x_labels = ["{:x}".format(o) for o in range(0, len(data[0]) if len(data) == 1 else pages_per_row)]
    file_offset_pages = int(file_offset / mmap.PAGESIZE)
    y_labels = ["0x{:x}".format(o) for o in range(file_offset_pages, file_offset_pages + len(data) * pages_per_row, pages_per_row)]

    # new plot
    fig, ax = plt.subplots()#figsize=())
    # use imshow
    im = ax.imshow(np.array(data), cmap=plt.cm.Greys, vmin=0, vmax=max_val)

    # create colorbar
    cbar = ax.figure.colorbar(im, ax=ax, ticks=range(0, max_val + 1))
    cbar.ax.set_ylabel("Hits", rotation=-90, va="bottom")

    # major ticks
    ax.set_xticks(range(len(x_labels)))
    ax.set_yticks(range(len(y_labels)))
    # label major ticks
    ax.set_xticklabels(x_labels)
    ax.set_yticklabels(y_labels)

    # minor ticks 
    ax.set_xticks(np.arange(-0.5, len(x_labels), 1), minor=True)
    ax.set_yticks(np.arange(-0.5, len(y_labels), 1), minor=True)
    # grid 
    ax.grid(which="minor", color="black", linestyle="-", linewidth=1)

    # title is file path
    ax.set_title(file_path)
    fig.tight_layout()
    
    if save:
        plt.savefig(os.path.basename(file_path) + ".hits" + ".pdf", dpi=300)
    if show:
        plt.show()
    plt.close()

    

parser = argparse.ArgumentParser(description="Decode '/proc/{pid}/maps' info.")
parser.add_argument("pid", type=int, help="pid of the target process to attach to")
parser.add_argument("samples", type=int, help="amount of samples")
parser.add_argument("--event_function", type=str, help="python expression for generating event")
parser.add_argument("--event_application", type=str, help="application for simulating event")
parser.add_argument("--event_user", action="store_true", help="wait until user triggers event")
parser.add_argument("--event_user_wait", type=int, help="amount of seconds to wait in case of user events")
args = parser.parse_args()
pid = args.pid

#print("Processing is started after 5 seconds...")
#time.sleep(5)

# load phyiscal pages needed for event execution if not already loaded
if args.event_user:
    input("Please execute event a few times and press enter...")

# freeze process (for parsing maps, getting pfns)
process_control = vmtools.ProcessControl(pid)
process_control.freeze()

# get executable, file-backed mappings (executable shared objects - shared libraries)
maps_reader = vmtools.MapsReader(pid)
maps = maps_reader.getMapsByPermissions(executable=True, only_file=True)

# initialise page mapping reader 
page_map_reader = vmtools.PageMapReader(pid)

# get pfns for maps 
for map in maps:
    vpn_low = int(map["addresses"][0] / mmap.PAGESIZE)
    vpn_high = int((map["addresses"][1] + mmap.PAGESIZE - 1) / mmap.PAGESIZE)
    pfns = []
    for vpn in range(vpn_low, vpn_high):
        mapping = page_map_reader.getMapping(vpn)
        if mapping[0].present:
            pfns.append(mapping[0].pfn_swap)
        else:
            pfns.append(-1)
    map["pfns"] = pfns
    map["pfns_accessed_no_event"] = [0] * len(pfns)
    map["pfns_accessed_event"] =  [0] * len(pfns)

# resume process
process_control.resume()

# initialse page usage tracker
page_usage_tracker = vmtools.PageUsageTracker()

print("Sampling noise floor:")
for i in tqdm.tqdm(range(args.samples)):
    # reset
    for map in maps:
        page_usage_tracker.resetPfns(map["pfns"])
    # sampling noise floor
    if args.event_user:
        print("Make noise...")
        time.sleep(3)
        print("Done")

    for map in maps:   
        state = page_usage_tracker.getPfnsState(map["pfns"])
        for i in range(len(state)):
            map["pfns_accessed_no_event"][i] += state[i]

print("Sampling event:")
for i in tqdm.tqdm(range(args.samples)):  
    # reset
    for map in maps:
        page_usage_tracker.resetPfns(map["pfns"])
    # sampling event
    if args.event_user:
        print("Trigger event...")
        time.sleep(3)
        print("Done")

    for map in maps:   
        state = page_usage_tracker.getPfnsState(map["pfns"])
        for i in range(len(state)):
            map["pfns_accessed_event"][i] += state[i]

# calculate difference
for map in maps:
    pfns_accessed_diff = [0] * len(map["pfns"])
    for i in range(len(pfns_accessed_diff)):
        pfns_accessed_diff[i] = map["pfns_accessed_event"][i] - map["pfns_accessed_no_event"][i]
    map["pfns_accessed_diff"] = pfns_accessed_diff

for map in maps:
   # print(map["path"])
    #print(map["pfns_accessed_diff"])
    ret = argmax(map["pfns_accessed_diff"])
    # skip all libraries without a highly likely target
    if ret[0] < 1:
        continue
    print("File: {} Max: {} at file page: 0x{:x}".format(map["path"], ret[0], int(map["file_offset"] / mmap.PAGESIZE) + ret[1]))
    createEventPageHitHeatmap(map["path"], map["file_offset"], map["pfns_accessed_diff"], args.samples, save=True)

# save all data 
with open("data/sample.json", "w") as file:
    file.write(json.dumps(maps))



# execute event

# step 1 find executable mappings 

# step 2 get pfns of these mappings and save correspondence 

# step 3 mark pfns idle 

# step 4 execute event 

# step 5 get back page status 

# do this multiple times 

# do it also without events 

# create heatmaps of library pages (showing #accessed_event - #accessed_wo_event)

# possible value range -samples to samples

# heatmap for every library