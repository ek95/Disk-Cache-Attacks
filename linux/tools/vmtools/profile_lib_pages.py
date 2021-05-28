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
import pdb


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
        vpn_sup = int((map["addresses"][1] + mmap.PAGESIZE - 1) / mmap.PAGESIZE)
        
        pfns = [-1] * (vpn_sup - vpn_low)
        for i, vpn in enumerate(range(vpn_low, vpn_sup)):
            mapping = page_map_reader.getMapping(vpn)
            if mapping[0].present:
                pfns[i] = mapping[0].pfn_swap
        map["pfns"] = pfns

    process_control.resume()
    return maps



def getEventClusterFitness(pfn_accesses_events, cluster_events, samples):
    # ideas:
    # min score of cluster elements is cluster score
    # if other events triggered randomly this could also come from some other operation
    #   -> general noise -> penality should not be too high if other events triggered less in comparision
    #   -> calculate their influence with rms
    raw_cluster = pfn_accesses_events[cluster_events]
    mask = np.ones(pfn_accesses_events.size, dtype=bool)
    mask[cluster_events] = False
    non_cluster = pfn_accesses_events[mask]

    min_cluster_score = np.min(raw_cluster)
    noise_score = np.sqrt(np.sum(non_cluster ** 2))

    raw_fitness = max(min_cluster_score - noise_score, 0)
    return (raw_fitness, raw_fitness / samples)

def getEventClusterDescriptor(cluster_events):
    descriptor = "-".join([str(x) for x in cluster_events])
    return descriptor

def processMapping(mapping, samples, cluster_size, fitness_threshold, event_to_file_page_mapping, event_to_file_page_candidates):
    for off in range(len(mapping["accessed_pfns_events"])):
        cluster_events = mapping["accessed_pfns_events_argsort"][off][:cluster_size]
        fitness = getEventClusterFitness(mapping["accessed_pfns_events"][off], cluster_events, samples)
        if fitness[1] > fitness_threshold:
            event_to_file_page_candidates[cluster_events] += 1
            event_cluster_descriptor = getEventClusterDescriptor(cluster_events)
            if not (event_cluster_descriptor in event_to_file_page_mapping):
                event_to_file_page_mapping[event_cluster_descriptor] = []
            event_to_file_page_mapping[event_cluster_descriptor].append({
                "events": cluster_events,
                "fitness": fitness,
                "path": mapping["path"], 
                "file_offset": mapping["file_offset"] + off * mmap.PAGESIZE,
                "current_pfn": mapping["pfns"][off]
            })
    return



def processEventDataSimple(events, pc_mappings, samples, fitness_threshold):
    # simple idea -> not very powerful (clustering algorithms, ml would be far more powerful)
    # but fits well with event-triggered eviction approach (periodic sampling is anyhow not wanted)
    #   -> we look at the classification problem page-per-page
    #       -> no detection of higher-order patterns!
    #   -> we want to have every event covered
    #   -> pages which accurately classify ONE event are preferred
    #       -> if not every event is covered, we search for (small) clusters
    #   -> continue until all events are covered or cluster search reached max. size 
    event_to_file_page_mapping = {}
    event_to_file_page_candidates = np.zeros(len(events))

    # fast path with cluster size 1
    for mapping in pc_mappings:
        # sort events number by score
        mapping["accessed_pfns_events_argsort"] = [np.argsort(-x) for x in mapping["accessed_pfns_events"]]
        processMapping(mapping, samples, 1, fitness_threshold, event_to_file_page_mapping, event_to_file_page_candidates)
    # stop if everything is classified already
    if not all(event_to_file_page_candidates):
        for cluster_size in range(2, len(events) + 1):
            print("Trying for cluster size {}".format(cluster_size))
            for mapping in pc_mappings:
                processMapping(mapping, samples, cluster_size, fitness_threshold, event_to_file_page_mapping, event_to_file_page_candidates)
            # stop everything is classified already
            if all(event_to_file_page_candidates):
                break

    # sort event_to_pfn mappings by fitness
    for array in event_to_file_page_mapping.values():
        array.sort(key=lambda x: x["fitness"], reverse=True)

    print(event_to_file_page_candidates)
    return event_to_file_page_mapping


def printEventFileOffsets(events, event_to_file_page_mapping, fitness_threshold):
    for event_file_pages in event_to_file_page_mapping.values():
        if len(event_file_pages) > 0 and event_file_pages[0]["fitness"][1] > fitness_threshold:
            event_string = ", ".join([events[e][0] for e in event_file_pages[0]["events"]])
            print("Event: {}".format(event_string))
        else:
            continue
        for event_file_page in event_file_pages:
            if event_file_page["fitness"][1] > fitness_threshold:
                print("Fitness: {}%, File: {}, Offset: 0x{:x}, Current PFN: 0x{:x}".format(event_file_page["fitness"][1] * 100, event_file_page["path"], event_file_page["file_offset"], event_file_page["current_pfn"]))


def dofakeEvent():
    # sleep a bit
    time.sleep(0.01)



def doUserEventNoInput():
    print("Trigger Event...")
    time.sleep(3)
    print("STOP") 
    time.sleep(1)
    print("!!!") 

def doUserEvent():
    print("Trigger Event....")
    input("Press key when ready...")


def doKeyboardEvent(key):
    #keyboard = Controller()
    #keyboard.press(KeyCode.from_char(key))
    #keyboard.release(KeyCode.from_char(key))
    keyboard.write(key)
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
    mapping["accessed_pfns_events"] = [np.zeros(len(events)) for _ in range(len(mapping["pfns"]))]

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

# process data
event_to_file_page_mapping = processEventDataSimple(events, pc_mappings, args.samples, 0.5)

# very simple just searches for pfns which describe a event best, i.e. its likely that only this event will set this pfn
#events_file_offsets = [ [] for _ in range(len(events)) ]
#for mapping in pc_mappings:
#    for off in range(len(mapping["accessed_pfns_events"])):
#        max2events = np.argsort(-np.array(mapping["accessed_pfns_events"][off]))[:2]
#        score = mapping["accessed_pfns_events"][off][max2events[0]] - mapping["accessed_pfns_events"][off][max2events[1]]
#        if score > 0:
#            events_file_offsets[max2events[0]].append((score, mapping["path"] , mapping["file_offset"] + off * mmap.PAGESIZE, mapping["pfns"][off]))

# sort + print
printEventFileOffsets(events, event_to_file_page_mapping, 0.5)


# save data
if args.save:
    results = {
        "event_strings": [e[0] for e in events],
        "raw_data": pc_mappings,
        "event_to_file_page_mapping": event_to_file_page_mapping
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