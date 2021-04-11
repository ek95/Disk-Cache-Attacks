#!/usr/bin/env python3
import argparse 
import vmtools
import mmap


parser = argparse.ArgumentParser(description="Read page mappings / contents of the target process.")
parser.add_argument("pid", type=int, help="pid of qemu process")
parser.add_argument("ram_size", type=int, help="ram size of guest in mb")
parser.add_argument("guest_pfns", type=str, nargs="+", help="pfn expressions")
parser.add_argument("-p", "--page", action="store_true", help="also get page content")
args = parser.parse_args()

pid = args.pid
# evaluate virtual address expression
guest_pfns = [eval(guest_pfn) for guest_pfn in args.guest_pfns]

# freeze process
process_control = vmtools.ProcessControl(pid)
process_control.freeze()

# maps reader
maps_reader = vmtools.MapsReader(pid)
# pagemap reader
page_map_reader = vmtools.PageMapReader(pid)
# mem reader
mem_reader = vmtools.MemReader(pid)
# hex dump printer
hex_dump_printer = vmtools.HexDumpPrinter(16, True)

# search for ram mapping 
qemu_ram_mapping = None
maps = maps_reader.getMapsBySize(args.ram_size * 1024 * 1024, only_anon=True)
if len(maps) > 1:
    print("Multiple possible mappings found, select one:")
    for i in range(len(maps)):
        print("[{}] {}-{}".format(i, maps[i]["addresses"][0], maps[i]["addresses"][1]))
    selection = input("> ")
    qemu_ram_mapping = maps[int(selection)]
else:
    qemu_ram_mapping = maps[0]
print("Found qemu ram mapping base address: 0x{:08x}\n".format(qemu_ram_mapping["addresses"][0]))

# process virtual addresses
for guest_pfn in guest_pfns:
    qemu_ram_base_vaddr = qemu_ram_mapping["addresses"][0]
    # qemu x64 memory maps: (0x0 - 0xbffdcfff), (0x100000000 - 0x13fffffff)  
    # for extended memory
    # vaddr = qemu_ram_base_vaddr + qemu_low_mem_size + guest_addr - qemu_extended_mem_begin_addr -> offset -1GB
    vaddr = (qemu_ram_base_vaddr - 0x40000000  if (guest_pfn > 0x100000) else qemu_ram_base_vaddr) + guest_pfn * mmap.PAGESIZE 
    
    print("Guest PFN: 0x{:08x}".format(guest_pfn))
    print("Host Vaddr: 0x{:08x}".format(vaddr))
    print("--------------------------------------------------------------------------------")
    (page_map, flags) = page_map_reader.getMapping(vaddr / mmap.PAGESIZE)
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