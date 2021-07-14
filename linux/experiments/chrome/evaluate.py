#!/usr/bin/env python3
import argparse
import json
from typing import Mapping
import numpy as np
import mmap
import pdb


FAULT_READAHEAD_WINDOW_PAGES=32
BACK_RA_WINDOW = int(FAULT_READAHEAD_WINDOW_PAGES / 2)
FRONT_RA_WINDOW = int(FAULT_READAHEAD_WINDOW_PAGES/ 2) - 1 
ACCEPT_RA_CORNER_PAGE_CH_THRESHOLD=0.1


parser = argparse.ArgumentParser(description="Evaluates page cache hit data.")
parser.add_argument("--profile", type=str, metavar=("path"),
                      help="loads profiling results from a json file")
parser.add_argument("--attack_conf", type=str, metavar=("path"),
                      help="creates attack configuration file")
args = parser.parse_args()

# load profile
if args.profile:
    results_json = None
    with open(args.profile, "r") as file:
        results_json = json.loads(file.read())
else:
    print("You have to specify a profile!")
    exit(-1)

# parse found file-page to event mappings
file_to_events={}
for event_mapping in results_json["optimal_event_file_offset_mappings"]:
    if not (event_mapping["file"] in file_to_events):
        file_to_events[event_mapping["file"]] = {}
    file_to_events[event_mapping["file"]][int(event_mapping["offset"] / mmap.PAGESIZE)] = event_mapping

# determine if we should use ra corner pages for evaluation
for file in file_to_events.keys():
    poffsets = sorted(file_to_events[file].keys())  
    for i in range(1, len(poffsets)):
        # page fault window overlaps, probe readahead corners as decision help
        # if their ch ratio is adequatly low
        if poffsets[i] - poffsets[i - 1] < FAULT_READAHEAD_WINDOW_PAGES:
            # add thresholds to both mappings if possible
            event_mapping = file_to_events[file][poffsets[i]]
            # threshold fullfils our requirements, we should consider corner pages
            if (event_mapping["ra_corner_pages_ch_ratios"][0][1] < ACCEPT_RA_CORNER_PAGE_CH_THRESHOLD and 
                event_mapping["ra_corner_pages_ch_ratios"][1][1] < ACCEPT_RA_CORNER_PAGE_CH_THRESHOLD):
                event_mapping["evaluate_ra_corners"] = True
            event_mapping = file_to_events[file][poffsets[i - 1]]
            # threshold fullfils our requirements, we should consider corner pages
            if (event_mapping["ra_corner_pages_ch_ratios"][0][1] < ACCEPT_RA_CORNER_PAGE_CH_THRESHOLD and 
                event_mapping["ra_corner_pages_ch_ratios"][1][1] < ACCEPT_RA_CORNER_PAGE_CH_THRESHOLD):
                event_mapping["evaluate_ra_corners"] = True

# creates attack configuration file out of profile
if args.attack_conf:
    with open(args.attack_conf, "w") as attack_conf_file:
        for file in file_to_events.keys():
            attack_conf_file.write(file + "\n")
            for poffset in sorted(file_to_events[file].keys()):
                event_mapping = file_to_events[file][poffset]
                if ("evaluate_ra_corners" in event_mapping and 
                    not event_mapping["ra_corner_pages_ch_ratios"][0][0] in file_to_events[file]):
                    attack_conf_file.write("{:x} {}\n".format(event_mapping["ra_corner_pages_ch_ratios"][0][0], 1))
                attack_conf_file.write("{:x} {}\n".format(poffset, 0))
                if ("evaluate_ra_corners" in event_mapping and 
                    not event_mapping["ra_corner_pages_ch_ratios"][1][0] in file_to_events[file]):
                    attack_conf_file.write("{:x} {}\n".format(event_mapping["ra_corner_pages_ch_ratios"][1][0], 1))
            attack_conf_file.write("\n")

# print mappings in a nice way
for file in file_to_events.keys():
    print(file)
    for poffset in sorted(file_to_events[file].keys()):
        print("{:x} -> {}".format(poffset, file_to_events[file][poffset]["event_group_labels"]))
    print("")