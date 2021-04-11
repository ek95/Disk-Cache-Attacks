#!/usr/bin/env python3 
import argparse
import vmtools
import mmap


# parse command line arguments
parser = argparse.ArgumentParser(description="Search a virtual memory region for page contents.")
parser.add_argument("pid", type=int, help="pid of the target process")
parser.add_argument("start_address", type=str, help="start address of virtual range")
parser.add_argument("range", type=str, help="search range in bytes")
parser.add_argument("--data_file", type=str, help="path to a file containing the data pages which should be found")
parser.add_argument("--data_expr", type=str, help="python expression which generates the data pages which should be found")
parser.add_argument("-s", "--short", action="store_true", help="print in short notation")
args = parser.parse_args()

pid = args.pid
# start virtual address + range
start_vaddr = eval(args.start_address)
search_range = eval(args.range)

# freeze process
process_control = vmtools.ProcessControl(pid)
process_control.freeze()

# open search data 
if args.data_file:
    with open(args.data_file, "rb") as file:
        # load search data 
        search_data = file.read()
elif args.data_expr:
    search_data = eval(args.data_expr)
else:
    print("You have to specify a data source!")
    exit(-1)

# open process memory
mem_fd = open(vmtools.PROCESS_MEM_PATH_TEMPLATE.format(pid), "rb")
# search for matching pages
for data_offset in range(0, len(search_data), mmap.PAGESIZE):
    # extract compare data 
    compare_data = search_data[data_offset : data_offset + mmap.PAGESIZE]
    if not args.short:
        print("Searching for file page 0x{:08x} in memory:".format(int(data_offset / mmap.PAGESIZE)))
    # seek to start of range
    mem_fd.seek(start_vaddr)
    for current_vaddr in range(start_vaddr, start_vaddr + search_range, mmap.PAGESIZE):
        # load
        mem_data = mem_fd.read(mmap.PAGESIZE)
        # compare data
        if mem_data == compare_data:
            if not args.short:
                print("Found at virtual address: 0x{:08x}".format(current_vaddr))
            else:
                print("0x{:08x}\t0x{:08x}".format(int(data_offset / mmap.PAGESIZE), current_vaddr))
# close 
mem_fd.close()

# resume process
process_control.resume()