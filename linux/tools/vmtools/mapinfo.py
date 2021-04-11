#!/usr/bin/env python3
import argparse 
import vmtools


parser = argparse.ArgumentParser(description="Decode '/proc/{pid}/maps' info.")
parser.add_argument("pid", type=int, help="pid of the target process")
args = parser.parse_args()

pid = args.pid

# freeze process
process_control = vmtools.ProcessControl(pid)
process_control.freeze()

# read memory maps of target process
maps_reader = vmtools.MapsReader(pid)
maps = maps_reader.getMaps()
for map in maps:
    print("0x{:08x} {}".format(map["addresses"][0], map["size"]))

# resume process
process_control.resume()