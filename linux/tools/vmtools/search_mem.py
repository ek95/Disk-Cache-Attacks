#!/usr/bin/env python3 
import argparse
import vmtools
import mmap
import pdb


# parse command line arguments
parser = argparse.ArgumentParser(description="Search a virtual memory region for page contents.")
parser.add_argument("pid", type=int, help="pid of the target process")
parser.add_argument("--data_file", type=str, help="path to a file containing the data pages which should be found")
parser.add_argument("--data_expr", type=str, help="python expression which generates the data pages which should be found")
parser.add_argument("--only_anon", action="store_true", help="only search anonymous map regions")
args = parser.parse_args()

pid = args.pid

# freeze process
process_control = vmtools.ProcessControl(pid)
process_control.freeze()

# read memory maps of target process
maps_reader = vmtools.MapsReader(pid)
maps = maps_reader.getMaps(only_anon=True if args.only_anon else False)
maps_len = len(maps)

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
search_data_len = len(search_data)

# open target process memory
mem_fd = open(vmtools.PROCESS_MEM_PATH_TEMPLATE.format(args.pid), "rb")
# go through memory regions
for r in range(maps_len):
    # get current map
    map = maps[r]
    current_vaddr = map["addresses"][0]
    to_read = map["size"]
   
    # search
    print("\33[2K\r[{} / {}] 0x{:08x} - 0x{:08x}:".format(r, maps_len - 1, map["addresses"][0], map["addresses"][1]), end="")
    # load first memory block (changed to support also offsets > 2**63 - 1)
    try:
        mem_fd.seek(vmtools.asClongCompatible(current_vaddr))
    except IOError as ex:
        if ex.errno == 0:
            pass 
        else:
            raise ex
    # skip not readable regions
    try:
        read_size = to_read if to_read < search_data_len else search_data_len
        new_block = mem_fd.read(read_size)
    except:
        print("\nI/O error at reading offset 0x{:08x} size 0x{:08x}".format(current_vaddr, read_size))
        print("Skipping map region...")
        continue
    block_size = len(new_block)
    current_vaddr += block_size
    to_read -= block_size
    found_addresses = []
    while True:
        # compare first block
        current_block = new_block
        if block_size < search_data_len:
            break
        elif current_block == search_data:
            found_addresses.append(current_vaddr)
        # no more blocks 
        if to_read == 0:
            break

        # load next block for compare window 
        try:
            read_size = to_read if to_read < search_data_len else search_data_len
            new_block = mem_fd.read(read_size)
        except:
            print("\nI/O error at reading offset 0x{:08x} size 0x{:08x}".format(current_vaddr, read_size))
            print("Skipping map region...")
            break
        block_size = len(new_block)
        current_vaddr += block_size
        to_read -= block_size
        search_window = current_block + new_block
        for of in range(1, block_size):
            if search_window[of : of + search_data_len] == search_data:
                found_addresses.append(current_vaddr + of)
        current_vaddr += search_data_len

    # print addresses
    if len(found_addresses) != 0:
        print("") 
    for addr in found_addresses:
        print("0x{:08x}".format(addr))        
# close 
mem_fd.close()

# resume process
process_control.resume()