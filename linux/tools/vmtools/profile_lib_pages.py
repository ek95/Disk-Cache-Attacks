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
import signal
import random
#os.environ["PYNPUT_BACKEND_KEYBOARD"] = "uinput"
#os.environ["PYNPUT_BACKEND_MOUSE"] = "dummy"
#from pynput.keyboard import Controller, KeyCode
import keyboard
import functools
import string


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


def targetGetPcMappings(pid):
    # freeze process (for parsing maps, getting pfns)
    process_control = vmtools.ProcessControl(pid)
    process_control.freeze()

    # get read-only, file-backed mappings 
    #   -> read-only data, shared libraries
    #   -> everything that for sure is shared using the page cache
    maps_reader = vmtools.MapsReader(pid)
    maps = maps_reader.getMapsByPermissions(read=True, write=False, only_file=True)

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

    process_control.resume()
    return maps



def calcFitScore(event, pfn_state_events, samples):
    score = max(2 * pfn_state_events[event] - sum(pfn_state_events), 0)
    return (score, score / samples)


def getEventClusterFitness(cluster_pfn_state, samples):
    raw_cluster = sum(cluster_pfn_state)
    normalized_cluster = raw_cluster / len(cluster_pfn_state)
    raw_fitness = max(2 * raw_cluster - sum(cluster_pfn_state), 0)
    return (raw_fitness, raw_fitness / samples)


def processMapping(mapping, samples, cluster_size, fit_score_threshold, event_to_pfn_mapping, event_pfn_candidates):
    for off in range(len(mapping["accessed_pfns_events"])):
        cluster_events = mapping["accessed_pfns_events_argsort"][off][:cluster_size]
        fitness = getEventClusterFitness(mapping["accessed_pfns_events"][off][cluster_events], samples)
        if fitness[1] > fit_score_threshold:
            event_pfn_candidates[cluster_events] += 1
            event_to_pfn_mapping.append({
                "events": cluster_events,
                "fitness": fitness,
                "path": mapping["path"], 
                "file_offset": mapping["file_offset"] + off * mmap.PAGESIZE,
                "current_pfn": mapping["pfns"][off]
            })

    return


def processEventDataSimple(events, pc_mappings, samples, fit_score_threshold):
    # simple idea -> not very powerful (clustering algorithms, ml would be far more powerful)
    # but fits well with event-triggered eviction approach (periodic sampling is anyhow not wanted)
    #   -> we look at the classification problem page-per-page
    #       -> no detection of higher-order patterns!
    #   -> we want to have every event covered
    #   -> pages which accurately classify ONE event are preferred
    #       -> if not every event is covered, we search for (small) clusters
    #   -> continue until all events are covered or cluster search reached max. size 
    event_to_pfn_mapping = []
    event_pfn_candidates = [0]

    # fast path with cluster size 1
    for mapping in pc_mappings:
        # sort accessed
        mapping["accessed_pfns_events_argsort"] = [np.argsort(-np.array(x)) for x in mapping["accessed_pfns_events"]]
        processMapping(mapping, samples, 1, fit_score_threshold, event_to_pfn_mapping, event_pfn_candidates)
    # stop everything is classified already
    if all(event_pfn_candidates ) != 0:
        break

    for cluster_size in range(2, len(events) + 1):
        for mapping in pc_mappings:
            processMapping(mapping, samples, cluster_size, fit_score_threshold, event_to_pfn_mapping, event_pfn_candidates)
        # stop everything is classified already
        if all(event_pfn_candidates ) != 0:
            break

    return event_to_pfn_mapping.sort(key=lambda x: x["fitness"], reverse=True)


def printEventFileOffsets(event_file_offsets, samples):
    for event_file_offset in event_file_offsets:
        score_percent = event_file_offset[0] / samples * 100
        if score_percent > 50: 
            print("Score: {}%, File: {}, Offset: 0x{:x}, Current PFN: 0x{:x}".format(event_file_offset[0] / samples * 100, event_file_offset[1], event_file_offset[2], event_file_offset[3]))


def doUserEventNoInput():
    print("Trigger Event...")
    time.sleep(3)
    print("STOP") 
    time.sleep(1)
    print("!!!") 


def doUserEvent():
    print("Trigger Event....")
    input("Press key when ready...")


def dofakeEvent():
    os.sched_yield()

def doKeyboardEvent(key):
    #keyboard = Controller()
    #keyboard.press(KeyCode.from_char(key))
    #keyboard.release(KeyCode.from_char(key))
    keyboard.write(key)
    # sleep a bit
    time.sleep(0.01)

def prepareKeyEvents():
    letters = string.digits + string.ascii_lowercase
    events = [ ("key_" + x, functools.partial(doKeyboardEvent, x)) for x in letters ]
    events.append(("fake", dofakeEvent))
    return events
        

# TODO modify
def autoCampaignPrepareEvents():
    return prepareKeyEvents()



parser = argparse.ArgumentParser(description="Profiles which pae offsets of files are accessed in case of an event.")
parser.add_argument("pid", type=int, help="pid of the target process to attach to")
parser.add_argument("samples", type=int, help="amount of samples")
parser.add_argument("--event_user", type=str, action="append", metavar=("NAME"), help="use manually triggered events (else coded in events are used)")
parser.add_argument("--event_user_no_input", action="store_true", help="do not ask for event completion, but use a wait time instead")
parser.add_argument("--tracer", action="store_true", help="starts a interactive tracer afterwards")
parser.add_argument("--save", type=str, help="saves results into json file")

#parser.add_argument("--event", type=str, action="append", nargs=2, metavar=("TYPE", "NAME"), help="python expression for generating event")
args = parser.parse_args()
pid = args.pid

signal.signal(signal.SIGINT, signal.default_int_handler)

# prepare events 
events = []
if args.event_user:
    events = [ (x, doUserEventNoInput if args.event_user_no_input else doUserEvent) for x in args.event_user ]
    input("Please execute events a few times and press enter (warms up page cache)...")
else:
    events = autoCampaignPrepareEvents()

# give user time to change focus, ...
print("Starting in 5s...")
time.sleep(5)

# get library mappings + pfns
pc_mappings = targetGetPcMappings(pid)

# debug print detected pc objects
# add accessed pfn matrix for each mapping 
for mapping in pc_mappings:
    #print(mapping["path"])
    mapping["accessed_pfns_events"] = [[0] * len(events) for _ in range(len(mapping["pfns"]))]

# sample all events
page_usage_tracker = vmtools.PageUsageTracker()
print("Sampling events:")
for _ in tqdm.tqdm(range(args.samples)):
    for event_i, event in random.sample(list(enumerate(events)), len(events)):
        print("Sampling event: " + event[0])
        # reset
        for mapping in pc_mappings:
            page_usage_tracker.resetPfns(mapping["pfns"])
    
        # run event function
        event[1]()

        # sample
        for mapping in pc_mappings:   
            state = page_usage_tracker.getPfnsState(mapping["pfns"])
            for off in range(len(state)):
                mapping["accessed_pfns_events"][off][event_i] += state[off]


# 
# process data
# very simple just searches for pfns which describe a event best, i.e. its likely that only this event will set this pfn
events_file_offsets = [ [] for _ in range(len(events)) ]
for mapping in pc_mappings:
    for off in range(len(mapping["accessed_pfns_events"])):
        max2events = np.argsort(-np.array(mapping["accessed_pfns_events"][off]))[:2]
        score = mapping["accessed_pfns_events"][off][max2events[0]] - mapping["accessed_pfns_events"][off][max2events[1]]
        if score > 0:
            events_file_offsets[max2events[0]].append((score, mapping["path"] , mapping["file_offset"] + off * mmap.PAGESIZE, mapping["pfns"][off]))
# sort + print
for i, event_file_offsets in enumerate(events_file_offsets): 
    # sort by score
    event_file_offsets.sort(key=lambda x: x[0], reverse=True)
    print("File offset combinations with a score > 50% for event {}:".format(events[i][0]))
    printEventFileOffsets(event_file_offsets, args.samples)


# save data
if args.save:
    results = {
        "raw_data": pc_mappings,
        "events_file_offsets": events_file_offsets
    }
    with open(args.save, "w") as file:
        file.write(json.dumps(results, indent=4))



# for debugging purposes
if args.tracer:
    while True:
        pfn = int(input("PFN to track (hex)> "), 16)
        page_usage_tracker.resetPfns([pfn])
        try:
            while True:
                current_time = time.time_ns()
                state = page_usage_tracker.getPfnsState([pfn])
                if state[0] == True:
                    print("[{}] Access detected!".format(current_time))
                    page_usage_tracker.resetPfns([pfn])
                os.sched_yield()
        except KeyboardInterrupt:
            pass


exit(0)

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