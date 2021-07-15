#!/usr/bin/env python3
import argparse 
import vmtools
import mmap


parser = argparse.ArgumentParser(description="Read page mappings / contents of the target process.")
parser.add_argument("pid", type=int, help="pid of the target process")
parser.add_argument("virtual_addresses", type=str, nargs="+", help="virtual address expressions")
parser.add_argument("-p", "--page", action="store_true", help="also get page content")
args = parser.parse_args()

pid = args.pid
# evaluate virtual address expression
virtual_addresses = [eval(vaddr) for vaddr in args.virtual_addresses]

# freeze process
process_control = vmtools.ProcessControl(pid)
process_control.freeze()

# pagemap reader
page_map_reader = vmtools.PageMapReader(pid)
# mem reader
mem_reader = vmtools.MemReader(pid)
# hex dump printer
hex_dump_printer = vmtools.HexDumpPrinter(16, True)

# process virtual addresses
for vaddr in virtual_addresses:
    print("0x{:08x}:".format(vaddr))
    print("--------------------------------------------------------------------------------")
    (page_map, flags) = page_map_reader.getMapping(int(vaddr / mmap.PAGESIZE))
    print("present: {}\nswapped: {}\nfile_shared: {}\nexclusive: {}\nsoft_dirty: {}\npfn_swap: {}"
          .format(page_map.present, page_map.swapped, page_map.file_shared, page_map.exclusive, 
          page_map.soft_dirty, page_map.pfn_swap))
    print("ksm: {}".format((flags >> 21) & 1))
    if args.page:
        data = mem_reader.getMem(vaddr, mmap.PAGESIZE)
        hex_dump_printer.print(data)  
    print("\n")

# resume process
process_control.resume()