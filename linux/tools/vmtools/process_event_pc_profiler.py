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



class Classifier:
    def __init__(self, fitness_threshold_train, fitness_threshold_print):
        self.fitness_threshold_train_ = fitness_threshold_train
        self.fitness_threshold_print_ = fitness_threshold_print
        self.events_ = None   
        self.samples_ = None
        self.pc_mappings_ = None

    def loadRawData(self, samples, pc_mappings):
        self.samples_ = samples
        self.pc_mappings_ = pc_mappings

    def collect(self, events, samples, pid):
        self.events_ = events
        self.samples_ = samples

        # get library mappings + pfns
        pc_mappings = targetGetPcMappings(pid)
        # prepare mapping objects for storing results
        self.collectPrepare_(pc_mappings)
       
        # sample all events
        page_usage_tracker = vmtools.PageUsageTracker()
        print("Sampling events:")
        for _ in tqdm.tqdm(range(self.samples_)):
            for event_i, event in random.sample(list(enumerate(self.events_)), len(self.events_)):
                # reset
                for mapping in pc_mappings:
                    page_usage_tracker.resetPfns(mapping["pfns"])
            
                # run event function
                event[1]()

                # sample
                for mapping in pc_mappings:   
                    pfn_state = page_usage_tracker.getPfnsState(mapping["pfns"])
                    self.collectMappingAdd_(mapping, pfn_state, event_i)

        self.pc_mappings_ = pc_mappings

    def collectPrepare_(self, pc_mappings):
        raise NotImplementedError("Needs to be overwritten!")

    def collectMappingAdd_(self, mapping, pfn_state, event):
        raise NotImplementedError("Needs to be overwritten!")

    def train(self):
        raise NotImplementedError("Needs to be overwritten!")

    def printResults(self):
        raise NotImplementedError("Needs to be overwritten!")


class SinglePageClassifier(Classifier):
    def __init__(self, fitness_threshold_train, fitness_threshold_print):
        super().__init__(fitness_threshold_train, fitness_threshold_print)
        self.pc_mappings_ = None
        self.event_to_file_page_mapping_ = None
        self.event_to_file_page_candidates_ = None

    def collectPrepare_(self, pc_mappings):
        # prepare mapping objects for storing results
        for mapping in pc_mappings:
            mapping["accessed_pfns_events"] = [np.zeros(len(self.events_)) for _ in range(len(mapping["pfns"]))]

    def collectMappingAdd_(self, mapping, pfn_state, event):
        for off in range(len(pfn_state)):
            mapping["accessed_pfns_events"][off][event] += pfn_state[off]

    def getEventClusterFitness(self, pfn_accesses_events, cluster_events):
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

        raw_fitness =np.max(min_cluster_score - noise_score, 0)
        return (raw_fitness, raw_fitness / self.samples_)

    def getEventClusterDescriptor(self, cluster_events):
        descriptor = "-".join([str(x) for x in cluster_events])
        return descriptor

    def processMapping(self, mapping, cluster_size):
        for off in range(len(mapping["accessed_pfns_events"])):
            cluster_events = mapping["accessed_pfns_events_argsort"][off][:cluster_size]
            fitness = self.getEventClusterFitness(mapping["accessed_pfns_events"][off], cluster_events)
            if fitness[1] > self.fitness_threshold_train_:
                self.event_to_file_page_candidates_[cluster_events] += 1
                event_cluster_descriptor = self.getEventClusterDescriptor(cluster_events)
                if not (event_cluster_descriptor in self.event_to_file_page_mapping_):
                    self.event_to_file_page_mapping_[event_cluster_descriptor] = []
                self.event_to_file_page_mapping_[event_cluster_descriptor].append({
                    "events": cluster_events.tolist(),
                    "fitness": fitness,
                    "path": mapping["path"], 
                    "file_offset": mapping["file_offset"] + off * mmap.PAGESIZE,
                    "current_pfn": mapping["pfns"][off]
                })
        return

    def train(self):
        # simple idea -> not very powerful (clustering algorithms, ml would be far more powerful)
        # but fits well with event-triggered eviction approach (periodic sampling is anyhow not wanted)
        #   -> we look at the classification problem page-per-page
        #       -> no detection of higher-order patterns!
        #   -> we want to have every event covered
        #   -> pages which accurately classify ONE event are preferred
        #       -> if not every event is covered, we search for (small) clusters
        #   -> continue until all events are covered or cluster search reached max. size 
        self.event_to_file_page_mapping_ = {}
        self.event_to_file_page_candidates_ = np.zeros(len(events))

        # fast path with cluster size 1
        for mapping in self.pc_mappings_:
            # sort events number by score
            mapping["accessed_pfns_events_argsort"] = [np.argsort(-x) for x in mapping["accessed_pfns_events"]]
            self.processMapping(mapping, 1)
        # stop if everything is classified already
        if not all(self.event_to_file_page_candidates_):
            for cluster_size in range(2, len(events) + 1):
                for mapping in self.pc_mappings_:
                    self.processMapping(mapping, cluster_size)
                # stop everything is classified already
                if all(self.event_to_file_page_candidates_):
                    break

        # sort event_to_pfn mappings by fitness
        for array in self.event_to_file_page_mapping_.values():
            array.sort(key=lambda x: x["fitness"], reverse=True)

        results = {
            "event_strings": [e[0] for e in self.events_],
            "raw_data": self.pc_mappings_,
            "event_to_file_page_mapping": self.event_to_file_page_mapping_
        }
        return results

    def printResults(self):
        for event_file_pages in self.event_to_file_page_mapping_.values():
            if len(event_file_pages) > 0 and event_file_pages[0]["fitness"][1] > self.fitness_threshold_print_:
                event_string = ", ".join([self.events_[e][0] for e in event_file_pages[0]["events"]])
                print("Event: {}".format(event_string))
            else:
                continue
            for event_file_page in event_file_pages:
                if event_file_page["fitness"][1] > self.fitness_threshold_print_:
                    print("Fitness: {}, File: {}, Offset: 0x{:x}, Current PFN: 0x{:x}".format(event_file_page["fitness"][1], event_file_page["path"], event_file_page["file_offset"], event_file_page["current_pfn"]))


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
    letters = string.digits #+ string.ascii_lowercase
    events = [ ("key_" + x, functools.partial(doKeyboardEvent, x)) for x in letters ]
    events.append(("fake", dofakeEvent))
    return events
        

# TODO modify
def autoCampaignPrepareEvents():
    return prepareKeyEvents()



parser = argparse.ArgumentParser(description="Profiles which pae offsets of files are accessed in case of an event.")
group_ex = parser.add_mutually_exclusive_group()
group_ex.add_argument("--collect", type=int, nargs=2, metavar=("pid", "samples"), help="collect data, pid + samples needed")
group_ex.add_argument("--load", type=str, help="loads raw results from a json file and processes them again")
parser.add_argument("--event_user", type=str, action="append", metavar=("NAME"), help="use manually triggered events (else coded in events are used)")
parser.add_argument("--event_user_no_input", action="store_true", help="do not ask for event completion, but use a wait time instead")
parser.add_argument("--tracer", action="store_true", help="starts a interactive tracer afterwards")
parser.add_argument("--save", type=str, help="saves results into json file")
args = parser.parse_args()

signal.signal(signal.SIGINT, signal.default_int_handler)

classifier = SinglePageClassifier(0.5, 0.5)

events = None 
pid = None 
samples = None
if args.load:
    results_json = None
    with open(args.load, "r") as file:
        results_json = json.loads(file.read())
    events = [(e , None) for e in results_json["events"]]
    pc_mappings = results_json["raw_trace"]
elif args.collect:
    pid = args.collect[0]
    samples = args.collect[1]

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

    # collect page access data from process
    classifier.collect(events, samples, pid)

# process data
results = classifier.train()
# print results
classifier.printResults()

# optional: save data
if args.save:
    with open(args.save, "w") as file:
        file.write(json.dumps(results, indent=4))

# optional: interactive pfn access state tracer
if args.tracer:
    page_usage_tracker = vmtools.PageUsageTracker()
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