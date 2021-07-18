#!/usr/bin/env python3
# NOTE locks examined memory-mapped files into memory
# TODO if target process maps a lot of files this might fail!
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
import keyboard
import functools
import string
import pdb


# wait a bit after a event was triggered to allow all accesses to happen
WAIT_AFTER_EVENT_S = 2
# wait longer in case of idle event (we also want to catch less frequent periodic page accesses)
IDLE_EVENT_WAIT_S = 30
FITNESS_THRESHOLD_TRAIN = 0.7
CH_RATIOS_SIMILAR_THRESHOLD = 0.1
CH_RATIOS_EVENTS_SIMILAR_THRESHOLD = 0.5
# how should the speculative reading of a larger page cluster at page faults be handled
# "none":   assume no page fault clustering exists
# "single-event": assume the attacker suppresssed the page fault clustering (by keeping surrounding pages active)
#                 and only one event occurs per sample 
#                 to help at classification, add pages which help the attacker to distinguish between
#                 event page fault clusters in case they are overlapping (and therefore can not be suppresssed)
#                 (== add fault cluster corner pages which help to determine which page triggered the 
#                  initial fault + only do this if these pages are otherwise not used)
#                 this only works if the events with overlapping fault cluster windows
#                 are assumed to be not triggered in parallel, further evaluation is left for the user
# "noise": trigger readahead as noise, substract the sum of ch ratios of pages that might trigger 
#          the caching of the current candidate page from its ch ratio
# linux default: 32 pages
HANDLE_FAULT_RA="single-event"
# linux 32 pages
FAULT_RA_WINDOW_PAGES=32



def createPageCacheHitHeatmap(event_cache_hits, page_range, mapping_page_offset, title,
    pages_per_row=16, show=True, save=False):
    # offset 
    offset  = page_range[0]
    length = page_range[1]
    # reorganize data
    data = [event_cache_hits[i : i + pages_per_row]
            for i in range(offset, offset + length, pages_per_row)]
    if len(data) > 1 and len(data[-1]) < pages_per_row:
        data[-1] = np.pad(data[-1], (0, pages_per_row - len(data[-1])))
    # generate x labels
    x_labels = ["{:x}".format(o) for o in range(
        0, len(data[0]) if len(data) == 1 else pages_per_row)]
    y_labels = ["0x{:x}".format(o) for o in range(
        mapping_page_offset + offset, mapping_page_offset + offset + len(data) * pages_per_row, pages_per_row)]

    # new plot
    fig, ax = plt.subplots()  # figsize=())
    # use imshow
    im = ax.imshow(np.array(data), cmap=plt.cm.Greys, vmin=0, vmax=1)

    # create colorbar
    cbar = ax.figure.colorbar(im, ax=ax, ticks=range(0, 1))
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
    ax.set_title(title)
    fig.tight_layout()

    if save:
        plt.savefig(title + ".pdf", dpi=300)
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
    maps = maps_reader.getMapsByPermissions(
        read=True, write=False, only_file=True)

    # merge overlapping file mappings if existing (reduces senseless computations)
    for m1 in range(len(maps) - 1):
        if maps[m1] is None:
            continue
        for m2 in range(m1 + 1, len(maps)):
            if (maps[m2] is not None and 
                maps[m1]["path"] == maps[m2]["path"]):
                # check if mappings overlap
                # order mappings by file start position
                if maps[m1]["file_offset"] <= maps[m2]["file_offset"]:
                    first_mapping = m1
                    second_mapping = m2
                else:
                    first_mapping = m2
                    second_mapping = m1 
                # check if overlapping
                if(maps[second_mapping]["file_offset"] < 
                    maps[first_mapping]["file_offset"] + maps[first_mapping]["size"]):
                    delta = ((maps[second_mapping]["file_offset"] + maps[second_mapping]["size"]) - 
                        (maps[first_mapping]["file_offset"] + maps[first_mapping]["size"]))
                    print("Merge")
                    pdb.set_trace()
                    # overlapping, merge
                    maps[first_mapping]["size"] += delta
                    maps[first_mapping]["addresses"][1] += delta
                    # mark second mapping for deletion
                    maps[second_mapping] = None 
            # might have been merged before
            if maps[m1] is None:
                break
    # filter None values
    maps = list(filter(None, maps))

    # mlock files into memory (so that pfn stays the same)
    # NOTE this might fail if too less physical memory is available
    locked_files = set()
    for map in maps:
        if map["path"] in locked_files:
            continue 
        try:
            map["mm"] = vmtools.mlockFile(map["path"])
        except FileNotFoundError:
            pass
        locked_files = map["path"]

    # initialise page mapping reader
    page_map_reader = vmtools.PageMapReader(pid)
    # get pfns for maps
    for map in maps:
        vpn_low = int(map["addresses"][0] / mmap.PAGESIZE)
        vpn_sup = int(
            (map["addresses"][1] + mmap.PAGESIZE - 1) / mmap.PAGESIZE)

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

        # warm-up page tables + page cache
        print("Executing events for warm-up...")
        for event in self.events_:
            event[1]()
        time.sleep(2)

        # get library mappings + pfns
        pc_mappings = targetGetPcMappings(pid)
        # prepare mapping objects for storing results
        self.collectPrepare_(pc_mappings)

        # sample all events
        print("Sampling events:")
        page_usage_tracker = vmtools.PageUsageTracker()
        for _ in tqdm.tqdm(range(self.samples_)):
            for event_i, event in random.sample(list(enumerate(self.events_)), len(self.events_)):
                # reset
                for mapping in pc_mappings:
                    page_usage_tracker.resetPfns(mapping["pfns"])

                # run event function
                event[1]()

                # sample
                for mapping in pc_mappings:
                    pfn_state = page_usage_tracker.getPfnsState(
                        mapping["pfns"])
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


# requires last event to be the "idle" event!
class SinglePageHitClassifier(Classifier):
    def __init__(self, fitness_threshold_train, ch_ratios_similar_threshold, ch_ratios_events_distinguishable_threshold,
        handle_fault_ra, fault_ra_window, debug_heatmaps = False):
        super().__init__(fitness_threshold_train)
        self.optimal_event_file_offset_mappings_ = None
        self.ch_ratios_similar_threshold_ = ch_ratios_similar_threshold
        self.ch_ratios_events_similar_threshold_ = ch_ratios_events_distinguishable_threshold
        self.handle_fault_ra_ = handle_fault_ra
        self.fault_ra_window_ = fault_ra_window
        self.debug_heatmaps_ = debug_heatmaps

    def collectPrepare_(self, pc_mappings):
        # prepare mapping objects for storing results
        for mapping in pc_mappings:
            # create event-access matrix
            mapping["events_pfn_accesses"] = np.zeros(
                (len(self.events_), len(mapping["pfns"])))

    def collectMappingAdd_(self, mapping, pfn_state, event):
        mapping["events_pfn_accesses"][event] += pfn_state

    def computeChRatios(self):
        for mapping in self.pc_mappings_:
            mapping["events_ch_ratios_raw"] = mapping["events_pfn_accesses"] / self.samples_
        

    def areEventsSimilar(self, events_ch_ratios):
        # short path: one event is always similar to itsself ;)
        if events_ch_ratios.shape[0] == 1:
            return True

        # caluclate differences between all unique event pairs
        differences = np.zeros(int(events_ch_ratios.shape[0] * (events_ch_ratios.shape[0] - 1) / 2))
        i = 0
        for e1 in range(events_ch_ratios.shape[0] - 1):
            for e2 in range(e1 + 1, events_ch_ratios.shape[0]):
                differences[i] = np.max(np.abs(events_ch_ratios[e1] - events_ch_ratios[e2]))
                i+=1

        # events are similar if the maximal value of the differences between 
        # all unique pairs is below a certain threshold
        return np.max(differences) <= self.ch_ratios_events_similar_threshold_

    def groupSimilarEvents(self):
        # check for each mapping
        for mapping in self.pc_mappings_:
            # process all events
            events_to_process = list(
                range(mapping["events_ch_ratios_raw"].shape[0]))
            mapping["events_ch_ratios_merged_header"] = {}
            mapping["events_ch_ratios_merged"] = np.zeros(
                (0, mapping["events_ch_ratios_raw"].shape[1]))
            
            while len(events_to_process) != 0:
                target_event = events_to_process.pop(0)
                merged_events = [target_event]
                not_merged_events = []
                for other_event in events_to_process:
                    candidate_events = merged_events + [other_event]
                    if self.areEventsSimilar(mapping["events_ch_ratios_raw"][candidate_events, :]):
                        # greedily collect merged events
                        # once merged they are one group as they are not distinguishable!
                        # if a new event makes the group distinguishable again, 
                        # then only because it does not belong to the group!
                        merged_events = candidate_events
                    else:
                        not_merged_events.append(other_event)

                # add merged events
                # (list contains at least 1 event -- in case the target event was not merged)
                if len(merged_events) not in mapping["events_ch_ratios_merged_header"]:
                    mapping["events_ch_ratios_merged_header"][len(merged_events)] = []
                mapping["events_ch_ratios_merged_header"][len(merged_events)].append(
                    (mapping["events_ch_ratios_merged"].shape[0], set(merged_events)))
                mapping["events_ch_ratios_merged"] = np.vstack((mapping["events_ch_ratios_merged"], 
                    np.mean(mapping["events_ch_ratios_raw"][merged_events, :], axis=0)))

                # continue processing with missing events
                events_to_process = not_merged_events        

    def getEventGroupLabel(self, event_group):
        return ", ".join([self.events_[x][0] for x in event_group])

    # negative ch ratios are not clipped, we anyhow only care about hits
    def findBestEventPageHitMappingByGroupSize(self, event, group_size, events_covered):
        best_candidate = None
        # check each mapping
        for mapping in self.pc_mappings_:
            # check event subgroups with wanted group size
            # does not exist -> skip mapping
            if group_size not in mapping["events_ch_ratios_merged_header"]:
                continue
            for row, event_subgroup in mapping["events_ch_ratios_merged_header"][group_size]:
                # is target event in subgroup at all?
                # is "idle" event (last event) in subgroup?
                # -> if so, continue
                if (event not in event_subgroup) or (len(self.events_) - 1 in event_subgroup):
                    continue

                # calculate event-fitness matrix 
                # events other than the target are treated as noise
                # noise is calculated using the root of the sum of the squared ch ratios of all other events 
                # this sum is always bigger than the maximum ch ratio but smaller than a comparable abs sum 
                # therefore, lower values are honored a bit less 
                # (not so realistic that all events are triggered during one sample run)
                #event_fitness = mapping["events_ch_ratios_merged"][row] - np.sqrt(np.sum(
                #    mapping["events_ch_ratios_merged"]**2, axis=0) - mapping["events_ch_ratios_merged"][row]**2)
                # events other than the target are treated as noise
                # noise is calculated using the sum of the ch ratios of all other events
                # (w.c. estimation, assumes all events are occuring in parallel)             
                event_fitness = mapping["events_ch_ratios_merged"][row] - (np.sum(
                    mapping["events_ch_ratios_merged"], axis=0) - mapping["events_ch_ratios_merged"][row])
                # handle readahead
                # (optionally) readahead window is treated as noise
                if self.handle_fault_ra_ == "noise":  
                    # TODO windows?
                    back_trigger_ra_window = int(self.fault_ra_window_ / 2) - 1    
                    front_trigger_ra_window = int(self.fault_ra_window_ / 2)  
                    event_fitness_ra = event_fitness.copy()
                    # use raw matrix, in later ones values are removed or merged which we do not want here
                    #rh_ch_sum = np.sqrt(np.sum(mapping["events_ch_ratios_raw"]**2, axis=0))
                    rh_ch_sum = np.sum(mapping["events_ch_ratios_raw"], axis=0)
                    for p in range(event_fitness.shape[0]):
                        # readahead behaves different inside the first possible window
                        # (front readahead increases if less than the default amount of back readahead was made
                        #  so that always fault_ra_window pages are read)
                        if p < self.fault_ra_window_:
                            #event_fitness_ra[p] = event_fitness[p] - np.sqrt(
                            #    np.sum(rh_ch_sum[p - (self.fault_ra_window_ - 1) : p]**2) + 
                            #    np.sum(rh_ch_sum[p + 1 : p + 1 + front_trigger_ra_window]**2)) 
                            event_fitness_ra[p] = event_fitness[p] - (
                                np.sum(rh_ch_sum[0 : p]) + 
                                np.sum(rh_ch_sum[p + 1 : p + 1 + front_trigger_ra_window]))                                 
                        else:
                            #event_fitness_ra[p] = event_fitness[p] - np.sqrt(
                            #    np.sum(rh_ch_sum[p - back_trigger_ra_window : p]**2) + 
                            #    np.sum(rh_ch_sum[p + 1 : p + 1 + front_trigger_ra_window]**2))  
                            event_fitness_ra[p] = event_fitness[p] - (
                                np.sum(rh_ch_sum[p - back_trigger_ra_window : p]) + 
                                np.sum(rh_ch_sum[p + 1 : p + 1 + front_trigger_ra_window]))                             
                    event_fitness = event_fitness_ra

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

                # find fault ra cluster corner pages
                # can be used to help classification in case of overlapping page fault clusters
                ra_corner_pages_ch_ratios = []
                if self.handle_fault_ra_ == "single-event":
                    # TODO windows?
                    back_ra_window = int(self.fault_ra_window_ / 2)
                    front_ra_window = int(self.fault_ra_window_ / 2) - 1 
                    # take the highest value either from the current mapping or idle
                    assist_ra_ch_ratios = np.maximum(mapping["events_ch_ratios_merged"][row], 
                        mapping["events_ch_ratios_raw"][-1])
                    if candidate_page < back_ra_window:
                        back_corner_page = 0 if candidate_page != 0 else -1
                        front_corner_page = min(candidate_page + front_ra_window + back_ra_window - candidate_page, mapping["events_ch_ratios_merged"][row].shape[0] - 1)   
                    else:
                        back_corner_page = candidate_page - back_ra_window
                        front_corner_page = min(candidate_page + front_ra_window, mapping["events_ch_ratios_merged"][row].shape[0] - 1)   
                    back_corner_ch_ratio = assist_ra_ch_ratios[back_corner_page] if back_corner_page != -1 else -1
                    front_corner_ch_ratio = assist_ra_ch_ratios[front_corner_page]
                    ra_corner_pages_ch_ratios=[(int(back_corner_page), float(back_corner_ch_ratio)), (int(front_corner_page), float(front_corner_ch_ratio))]

                #  better candidate -> remember
                best_candidate = {
                    "fitness": candidate_page_fitness,
                    "ch_ratio": mapping["events_ch_ratios_merged"][row][candidate_page],
                    "ra_corner_pages_ch_ratios": ra_corner_pages_ch_ratios,
                    "file": mapping["path"],
                    "offset": mapping["file_offset"] + candidate_page * mmap.PAGESIZE,
                    "current_pfn": mapping["pfns"][candidate_page],
                    "event_group": event_subgroup,
                    "event_group_filtered": candidate_group,
                    "event_group_labels": self.getEventGroupLabel(event_subgroup),
                    "event_group_filtered_labels": self.getEventGroupLabel(candidate_group),
                    "link_to_mapping": mapping
                }

        return best_candidate

    def findEventSinglePageHitMappings(self):
        found_optimal_mappings = []
        # last event is always "idle" event 
        #   -> not classified with this classifier
        events_to_search = set(range(len(self.events_)-1))
        events_covered = set()

        # try to find the best single pages that describe our events
        # start out with minimal event group size
        #   -> if no canidate is found increase it and retry 
        #      ("idle" event should not be part of any group, therefore no + 1)
        for group_size in range(1, len(self.events_)):
            events_to_search_next = set()
            while len(events_to_search) > 0:
                target_event = events_to_search.pop()
                best_candidate = self.findBestEventPageHitMappingByGroupSize(
                    target_event, group_size, events_covered)
                # either a candidate is found for this event and group size
                # or we have to try again with a larger group size
                if best_candidate is None:
                    # add again -> no candidate was found
                    events_to_search_next.add(target_event)
                else:
                    events_covered = events_covered.union(
                        best_candidate["event_group"])
                    events_to_search -= best_candidate["event_group"]
                    found_optimal_mappings.append(best_candidate)
            events_to_search = events_to_search_next

        # also return events_to_search which contains events for which no mapping 
        # was found
        return found_optimal_mappings, list(events_to_search)

    def train(self):
        # 1. Compute raw cache-hit ratios
        self.computeChRatios()
        # 2. Group similar events
        self.groupSimilarEvents()
        # 3. Search optimal set of event-page-hit mappings to describe events
        #   -> fails if not all events are describeable using single page hits
        self.optimal_event_file_offset_mappings_, events_no_mapping = self.findEventSinglePageHitMappings()
        if len(events_no_mapping) != 0:
            print("WARNING - not for every event a suitable page was found:")
            print(self.getEventGroupLabel(events_no_mapping))
        results = {
            "samples": self.samples_,
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
            print("Event Group (raw): {}".format(
                optimal_mapping["event_group_labels"]))
            print("Event Group (filtered): {}".format(
                optimal_mapping["event_group_filtered_labels"]))
            print("Fitness: {}".format(optimal_mapping["fitness"]))
            print("File Path: {} Offset: 0x{:x} Current PFN: 0x{:x}".format(
                optimal_mapping["file"], optimal_mapping["offset"], optimal_mapping["current_pfn"]))
            print("")   
            
        # (Optional Debug) Print raw ch heatmaps for all events in vicinity of selected page
        # allow visual inspection to ensure algorithm works right
        if self.debug_heatmaps_:
            for result in self.optimal_event_file_offset_mappings_:
                print("Event Group (raw): {}".format(result["event_group_labels"]))
                print("File Path: {} Offset: 0x{:x}".format(
                    result["file"], result["offset"]))
                mapping_offset_pages = int(result["link_to_mapping"]["file_offset"] / mmap.PAGESIZE)
                candidate_page = int(result["offset"] / mmap.PAGESIZE) - mapping_offset_pages
                show_page_range_start = candidate_page - 128           
                show_page_range_start = 0 if show_page_range_start < 0 else show_page_range_start
                show_page_range_len = int(result["link_to_mapping"]["size"] / mmap.PAGESIZE) - show_page_range_start
                show_page_range_len = 256 if show_page_range_len > 256 else show_page_range_len
                for event in result["event_group"]:
                    createPageCacheHitHeatmap(result["link_to_mapping"]["events_ch_ratios_raw"][event], 
                        (show_page_range_start, show_page_range_len), mapping_offset_pages, 
                        self.events_[event][0] + "\n" + result["file"])
                input("Press key for next event group...\n")

def doFakeEvent():
    # sleep a bit
    time.sleep(IDLE_EVENT_WAIT_S)


def doUserEventNoInput(event):
    print("Trigger Event: " + event)
    time.sleep(3)
    print("STOP")
    time.sleep(1)
    print("!!!")

def doUserEvent(event):
    print("Trigger Event: " + event)
    input("Press key when ready...")


def doKeyboardEvent(sc):
    keyboard.press(sc)
    keyboard.release(sc)
    time.sleep(WAIT_AFTER_EVENT_S)


def prepareKeyEvents():
    # main part of keyboard - except extended scancode keys
    scan_codes = [0x29]#, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 
        #0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 
        #0x3a, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x2b, 
        #0x2a, 0x56, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 
        #0x1d, 0x38, 0x39]
    events = [("sc_" + hex(x), functools.partial(doKeyboardEvent, x))
              for x in scan_codes]
    events.append(("fake", doFakeEvent))
    return events


# last event should be "idle" event!
def autoCampaignPrepareEvents():
    return prepareKeyEvents()


parser = argparse.ArgumentParser(
    description="Profiles which page offsets of shared files are accessed in case of an event.")
group_ex = parser.add_mutually_exclusive_group()
group_ex.add_argument("--collect", type=int, nargs=2, metavar=("pid",
                      "samples"), help="collect data: pid + samples needed")
group_ex.add_argument("--load", type=str, metavar=("path"),
                      help="loads raw results from a json file and processes them again")
parser.add_argument("--event_user", type=str, action="append", metavar=("NAME"),
                    help="use manually triggered events (else coded in events are used)")
parser.add_argument("--event_user_no_input", action="store_true",
                    help="do not ask for event completion, but use a wait time instead")
parser.add_argument("--tracer", action="store_true",
                    help="starts a interactive tracer afterwards")
parser.add_argument("--save", type=str, help="saves results into json file")
args = parser.parse_args()

if not (args.collect or args.load) and not args.tracer:
    parser.print_usage()
    exit(-1)

signal.signal(signal.SIGINT, signal.default_int_handler)

classifier = SinglePageHitClassifier(FITNESS_THRESHOLD_TRAIN, CH_RATIOS_SIMILAR_THRESHOLD, 
    CH_RATIOS_EVENTS_SIMILAR_THRESHOLD, HANDLE_FAULT_RA, FAULT_RA_WINDOW_PAGES, False)

events = None
pid = None
samples = None
if args.load:
    results_json = None
    with open(args.load, "r") as file:
        results_json = json.loads(file.read())
    samples = results_json["samples"]
    events = [(e, None) for e in results_json["event_strings"]]
    pc_mappings = results_json["raw_data"]
    for mapping in pc_mappings:
        mapping["events_pfn_accesses"] = np.array(mapping["events_pfn_accesses"])
   
    # load saved raw data
    classifier.loadRawData(events, samples, pc_mappings)
    # process data
    # requires last event to be the "idle" event!
    results = classifier.train()
    # print results
    classifier.printResults()
elif args.collect:
    pid = args.collect[0]
    samples = args.collect[1]
    # prepare events
    events = []
    if args.event_user:
        events = [(x, functools.partial(doUserEventNoInput, x) if args.event_user_no_input 
                    else functools.partial(doUserEvent, x))
                    for x in args.event_user]
    else:
        events = autoCampaignPrepareEvents()

    # give user time to change focus, ...
    print("Starting in 5s...")
    time.sleep(5)

    # collect page access data from process
    classifier.collect(events, samples, pid)
    # process data
    # requires last event to be the "idle" event!
    results = classifier.train()
    # print results
    classifier.printResults()

# optional: save data
# transform numpy to python structures
if args.save:
    for mapping in results["raw_data"]:
        mapping["events_pfn_accesses"] = [x.tolist()
                                           for x in mapping["events_pfn_accesses"]]
        # remove not needed data
        del mapping["events_ch_ratios_raw"]
        del mapping["events_ch_ratios_merged_header"]
        del mapping["events_ch_ratios_merged"]  
        if "mm" in mapping:
            del mapping["mm"]
    for mapping in results["optimal_event_file_offset_mappings"]: 
        mapping["offset"] = int(mapping["offset"])
        mapping["event_group"] = list(mapping["event_group"])
        mapping["event_group_filtered"] = list(mapping["event_group_filtered"])
        # remove not needed data
        del mapping["link_to_mapping"]
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
