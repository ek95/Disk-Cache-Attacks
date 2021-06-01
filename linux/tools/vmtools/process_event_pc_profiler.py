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
    def __init__(self, fitness_threshold_train):
        self.fitness_threshold_train_ = fitness_threshold_train
        self.events_ = None   
        self.samples_ = None
        self.pc_mappings_ = None

    def loadRawData(self, events, samples, pc_mappings):
        self.events_ = events
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


# generates unique event subgroups of a given size from a given event alphabet
class EventSubgroupGenerator(object):
    def __init__(self, event_alphabet, group_size):
        self.event_alphabet_ = event_alphabet
        self.alphabet_size_ = len(self.event_alphabet_)
        self.group_size_ = group_size
        self.generator_clock_ = list(range(group_size))
        self.exhausted_ = False

    def __iter__(self):
        return self

    def __next__(self):
        return self.next()

    def tickGeneratorClock(self):
        back_prob_start_pos = len(self.generator_clock_)
        # tick
        for tick_pos in range(len(self.generator_clock_) - 1, -1, -1):
            self.generator_clock_[tick_pos] += 1
            # no overflow -> ok end
            if self.generator_clock_[tick_pos] != self.alphabet_size_:
                break
            # overflow -> continue, save back prop position
            back_prob_start_pos = tick_pos
        # backprob -> fix values
        # exhausted?
        if back_prob_start_pos == 0:
            return True
        for back_prob_pos in range(back_prob_start_pos, len(self.generator_clock_)):
            self.generator_clock_[back_prob_pos] = self.generator_clock_[back_prob_pos - 1] + 1
            # exhausted ? 
            if self.generator_clock_[back_prob_pos] == self.alphabet_size_:
                return True 
        return False

    def next(self):
        if self.exhausted_:
            raise StopIteration()
        # subsample
        ret = [self.event_alphabet_[idx] for idx in self.generator_clock_]
        # tick generator clock
        self.exhausted_ = self.tickGeneratorClock()
        return ret


class SinglePageClassifier(Classifier):
    def __init__(self, fitness_threshold_train, ch_ratios_filter_threshold):
        super().__init__(fitness_threshold_train)
        self.optimal_event_file_offset_mappings_ = None
        self.ch_ratios_filter_threshold_ = ch_ratios_filter_threshold

    def collectPrepare_(self, pc_mappings):
        # prepare mapping objects for storing results
        for mapping in pc_mappings:
            # event-access matrix
            mapping["events_pfn_accesses"] = np.zeros((len(self.events_), len(mapping["pfns"])))

    def collectMappingAdd_(self, mapping, pfn_state, event):
        mapping["events_pfn_accesses"][event] += pfn_state

    def computeChRatios(self):
        for mapping in self.pc_mappings_:
            mapping["events_ch_ratio_raw"] = mapping["events_pfn_accesses"] / self.samples_ 

    def filterPfnsWithSimilarChRatio(self):
        for mapping in self.pc_mappings_:
            # get min ch ratio per address
            min_ch_ratios = np.min(mapping["events_ch_ratio_raw"], axis=0)
            # get max ch ratio per address
            max_ch_ratios = np.max(mapping["events_ch_ratio_raw"], axis=0)
            # get diff
            diff = max_ch_ratios - min_ch_ratios
            # is difference small -> common loaded pages -> remove (set ch ratio to zero)
            remove = diff < self.ch_ratios_filter_threshold_ 
            # set cells to zero 
            mapping["events_ch_ratio_filtered"] = mapping["events_ch_ratio_raw"]
            mapping["events_ch_ratio_filtered"][:,remove] = np.zeros((mapping["events_ch_ratio_raw"].shape[0], np.sum(remove)))

    def areEventsSimilar(self, events_ch_ratio):
        # short path: one event is always similar to its self ;)
        if events_ch_ratio.shape[0] == 1:
            return True

        mean_ch_ratio = np.mean(events_ch_ratio, axis=0)
        abs_diff = np.abs(events_ch_ratio - mean_ch_ratio * np.ones((events_ch_ratio.shape[0],1)))
        return np.all(abs_diff < self.ch_ratios_filter_threshold_)

    def groupSimilarEvents(self):
        # check for each mapping
        for mapping in self.pc_mappings_:
            events_to_process = list(range(mapping["events_ch_ratio_filtered"].shape[0]))
            mapping["events_ch_ratio_merged_header"] = {}
            mapping["events_ch_ratio_merged"] = np.zeros((0, mapping["events_ch_ratio_filtered"].shape[1]))
            # top down approach
            # start by evaluating if all events are the same
            #   -> metric: to all events have a small absolut difference compared to their mean?
            # yes: stop we only have one detectable group
            # no: evaluate subgroups
            event_subgroup_queue = [events_to_process]
            # keep track of processed subgroups to avoid double evaluation
            added_subgroups = {frozenset(events_to_process)}
            while len(event_subgroup_queue) != 0:
                event_subgroup = event_subgroup_queue.pop(0)
                # similar -> add merged group
                if self.areEventsSimilar(mapping["events_ch_ratio_filtered"][event_subgroup]):
                    if not (len(event_subgroup) in mapping["events_ch_ratio_merged_header"]):
                        mapping["events_ch_ratio_merged_header"][len(event_subgroup)] = []
                    mapping["events_ch_ratio_merged_header"][len(event_subgroup)].append((mapping["events_ch_ratio_merged"].shape[0], {*event_subgroup}))
                    mapping["events_ch_ratio_merged"] = np.vstack((mapping["events_ch_ratio_merged"], np.mean(mapping["events_ch_ratio_filtered"][event_subgroup,:], axis=0)))
                # not similar -> we have to go down to smaller subgroups
                else:
                    for new_subgroup in EventSubgroupGenerator(event_subgroup, len(event_subgroup) - 1):
                        new_subgroup_fs = frozenset(new_subgroup)
                        if new_subgroup_fs not in added_subgroups:
                            event_subgroup_queue.append(new_subgroup)
                            added_subgroups.add(new_subgroup_fs)

    def getEventGroupLabel(self, event_group):
        return ", ".join([self.events_[x][0] for x in event_group])

    def findBestEventPageMappingByGroupSize(self, event, group_size, events_covered):
        best_candidate = None
        # check each mapping
        for mapping in self.pc_mappings_:  
            # check event subgroups with wanted group size 
            # does not exist -> skip mapping
            if group_size not in mapping["events_ch_ratio_merged_header"]:
                continue          
            for row, event_subgroup in mapping["events_ch_ratio_merged_header"][group_size]:
                # is target event in subgroup at all?
                # -> no, continue
                if event not in event_subgroup:
                    continue

                # calculate event-fitness matrix (events other than the target are treated as noise)
                event_fitness = mapping["events_ch_ratio_merged"][row] - np.sqrt(np.sum(mapping["events_ch_ratio_merged"]**2, axis=0) - mapping["events_ch_ratio_merged"][row]**2)
                candidate_page = np.argmax(event_fitness)
                candidate_page_fitness = event_fitness[candidate_page]
                # does not fullfil our minimum requirements -> continue
                if candidate_page_fitness <= self.fitness_threshold_train_:
                    continue
                candidate_group = event_subgroup - events_covered
                candidate_group_size = len(candidate_group)
                # not better than what we already have -> continue
                if (best_candidate and 
                    candidate_group_size >= len(best_candidate["event_group_filtered"]) and 
                    candidate_page_fitness <= best_candidate["fitness"]):
                    continue

                #  better candidate -> remember
                best_candidate = {
                    "fitness": candidate_page_fitness,
                    "file": mapping["path"],
                    "offset": mapping["file_offset"] + candidate_page * mmap.PAGESIZE,
                    "current_pfn": mapping["pfns"][candidate_page],
                    "event_group": event_subgroup,
                    "event_group_filtered": candidate_group,
                    "event_group_labels": self.getEventGroupLabel(event_subgroup),
                    "event_group_filtered_labels": self.getEventGroupLabel(candidate_group)
                }

        return best_candidate

    def findEventSinglePageMappings(self):
        found_optimal_mappings = []
        events_to_search = set(range(len(self.events_)))
        events_covered = set()

        # try to find the best single pages that describe our events
        # start out with minimal event group size
        #   -> if no canidate is found increase it and retry
        for group_size in range(1, len(self.events_) + 1):
            events_to_search_next = set()
            while len(events_to_search) > 0:
                target_event = events_to_search.pop()
                best_candidate = self.findBestEventPageMappingByGroupSize(target_event, group_size, events_covered)
                if best_candidate is None:
                    events_to_search_next.add(target_event)
                else:
                    events_covered = events_covered.union(best_candidate["event_group"])
                    events_to_search -= best_candidate["event_group"]
                    found_optimal_mappings.append(best_candidate)
            events_to_search = events_to_search_next

        if len(events_to_search) != 0:
            return None
        
        return found_optimal_mappings

    def train(self):
        # 1. Compute raw cache-hit ratios
        self.computeChRatios()
        # 2. Filter pfns with similar ch ratio
        #   -> set all ch ratios accross events to zero
        self.filterPfnsWithSimilarChRatio()
        # 3. Group similar events
        #   -> metric: all events have small deviation from their mean
        self.groupSimilarEvents()
        # 4. Search optimal set of event-page mappings to describe events
        #   -> fails if not all events are somehow describeable using single pages
        self.optimal_event_file_offset_mappings_ = self.findEventSinglePageMappings()
        if self.optimal_event_file_offset_mappings_ is None:
            print("Training failed - could not find suitable pages!")
            return None 
        results = {
            "event_strings": [e[0] for e in self.events_],
            "raw_data": self.pc_mappings_,
            "optimal_event_file_offset_mappings": self.optimal_event_file_offset_mappings_
        }
        return results

    def printResults(self):
        if self.optimal_event_file_offset_mappings_ is None:
            print("No results available!")
            return
        print("")
        for optimal_mapping in self.optimal_event_file_offset_mappings_:
            print("Event Group (raw): {}".format(optimal_mapping["event_group_labels"]))
            print("Event Group (filtered): {}".format(optimal_mapping["event_group_filtered_labels"]))
            print("Fitness: {}".format(optimal_mapping["fitness"]))
            print("File Path: {} Offset: 0x{:x} Current PFN: 0x{:x}".format(optimal_mapping["file"], optimal_mapping["offset"], optimal_mapping["current_pfn"]))
            print("")


def dofakeEvent():
    # sleep a bit
    time.sleep(0.1)


def doUserEventNoInput():
    print("Trigger Event...")
    time.sleep(3)
    print("STOP") 
    time.sleep(1)
    print("!!!") 

def doUserEvent():
    print("Trigger Event....")
    input("Press key when ready...")


def doKeyboardEvent(sc):
    #keyboard = Controller()
    keyboard.press(sc)
    keyboard.release(sc)
    #keyboard.write(key)
    time.sleep(0.1)

def prepareKeyEvents():
    scan_codes = [0x29, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
        0x0c, 0x0d, 0x0e, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19]#, # 0x0f <- tab
        #0x1a, 0x1b, 0x1c, 0x3a, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26,
        #0x27, 0x28, 0x2b, 0x2a, 0x56, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33,
        #0x34, 0x35, 0x36, 0x1d, 0x38, 0x39, 0xe038, 0xe05d, 0xe01d]
    events = [ ("sc_" + hex(x), functools.partial(doKeyboardEvent, x)) for x in scan_codes ]
    events.append(("fake", dofakeEvent))
    return events
        

# TODO modify
def autoCampaignPrepareEvents():
    return prepareKeyEvents()



parser = argparse.ArgumentParser(description="Profiles which pae offsets of files are accessed in case of an event.")
group_ex = parser.add_mutually_exclusive_group()
group_ex.add_argument("--collect", type=int, nargs=2, metavar=("pid", "samples"), help="collect data, pid + samples needed")
group_ex.add_argument("--load", type=str, metavar=("path to stored results"), help="loads raw results from a json file and processes them again")
parser.add_argument("--event_user", type=str, action="append", metavar=("NAME"), help="use manually triggered events (else coded in events are used)")
parser.add_argument("--event_user_no_input", action="store_true", help="do not ask for event completion, but use a wait time instead")
parser.add_argument("--tracer", action="store_true", help="starts a interactive tracer afterwards")
parser.add_argument("--save", type=str, help="saves results into json file")
args = parser.parse_args()

signal.signal(signal.SIGINT, signal.default_int_handler)

classifier = SinglePageClassifier(0.6, 0.1)

events = None 
pid = None 
samples = None
if args.load:
    results_json = None
    with open(args.load, "r") as file:
        results_json = json.loads(file.read())
    events = [(e , None) for e in results_json["events"]]
    pc_mappings = results_json["raw_trace"]
    # load saved raw data
    classifier.loadRawData(events, samples, pc_mappings)
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
else:
    print("Wrong usage: Consult help.")
    exit(-1)

# process data
results = classifier.train()
# print results
classifier.printResults()

# optional: save data
# transform numpy to python structures
if args.save:
    for mapping in results["raw_data"]:
        mapping["accessed_pfns_events"] = [x.tolist() for x in mapping["accessed_pfns_events"]]
        del mapping["accessed_pfns_events_argsort"]
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