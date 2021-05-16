from ctypes import *
import os 
import signal


# convert python int value to c long compatible int
def asClongCompatible(value):
    value = int(value)
    if value > 2**63 - 1:
        return -(2**64 - value)
    else:
        return value 


# ctype extension
class StructureExt(Structure):
    def pack(self):
        return bytes(self)

    def unpack(self, bytes):
        fit = min(len(bytes), sizeof(self))
        memmove(addressof(self), bytes, fit)


# fs/proc/task_mmu.c
class PageMapEntry(StructureExt):
	_fields_ = [("pfn_swap", c_uint64, 55),
                ("soft_dirty", c_uint64, 1), 
                ("exclusive", c_uint64, 1),
                ("zero", c_uint64, 4),
                ("file_shared", c_uint64, 1),
                ("swapped", c_uint64, 1),
                ("present", c_uint64, 1)]


PROCESS_STAT_PATH_TEMPLATE = "/proc/{}/stat"
PROCESS_MAPS_PATH_TEMPLATE = "/proc/{}/maps"
PROCESS_PAGEMAP_PATH_TEMPLATE = "/proc/{}/pagemap"
PROCESS_MEM_PATH_TEMPLATE = "/proc/{}/mem"
KPAGEFLAGS_PATH = "/proc/kpageflags"
PAGE_IDLE_BITMAP_PATH = "/sys/kernel/mm/page_idle/bitmap"

class ProcessControl:
    def __init__(self, pid = None):
        self.pid_ = pid 

    def connect(self, pid):
        self.pid_ = pid 

    def freeze(self):
        # signal SIGSTOP (freeze process)
        os.kill(self.pid_, signal.SIGSTOP)
        # wait for stop of process
        with open(PROCESS_STAT_PATH_TEMPLATE.format(self.pid_), "r") as file:
            while True:
                file.seek(0)
                status_str = file.read()
                if status_str.split(" ")[2] == "T":
                    break 
                os.sched_yield()

    def resume(self):
        os.kill(self.pid_, signal.SIGCONT)


class MapsReader:
    def __init__(self, pid = None):
        self.maps_ = None 
        if pid is not None:
            self.parse(pid)

    def parse(self, pid):
        maps = []
        with open(PROCESS_MAPS_PATH_TEMPLATE.format(pid), "r") as file: 
            maps_content = file.read()
        maps_lines = maps_content.split("\n")
        for line in maps_lines:
            # skip empty lines
            if line == "":
                continue
            # process memory regions
            tokens = line.split()
            addresses = [int(token, 16) for token in tokens[0].split("-")]
            maps.append({"addresses": addresses, "size": addresses[1] - addresses[0], 
                         "perms": tokens[1], "file_offset": int(tokens[2], 16), 
                         "inode": int(tokens[4]), "path": "" if len(tokens) < 6 else tokens[5]})
        self.maps_ = maps

    def getMapsBySize(self, size, only_file=False, only_anon=False):
        found = []
        for map in self.maps_:
            if(map["size"] == size and 
               (not only_anon or map["inode"] == 0) and 
               (not only_file or map["inode"] != 0)):
                found.append(map)
        return found

    def getMapsByAddr(self, addr, only_file=False, only_anon=False):
        found = []
        for map in self.maps_:
            if(addr >= map["addresses"][0] and addr <= map["addresses"][1]
               and (not only_anon or map["inode"] == 0) 
               and (not only_file or map["inode"] != 0)):
                found.append(map)
        return found

    def getMapsByPermissions(self, read=False, write=False, executable=False, only_file=False, only_anon=False):
        found = []
        for map in self.maps_:
            if((not read or map["perms"][0] == 'r') and 
               (not write or map["perms"][1] == 'w') and
               (not executable or map["perms"][2] == 'x') and 
               (not only_anon or map["inode"] == 0) and 
               (not only_file or map["inode"] != 0)):
                found.append(map)
        return found

    def getMaps(self, only_file=False, only_anon=False):
        if not only_anon and not only_file:
            return self.maps_

        found = []
        for map in self.maps_:
            if((not only_anon or map["inode"] == 0) and 
               (not only_file or map["inode"] != 0)):
                found.append(map)
                
        return found


# https://github.com/torvalds/linux/blob/master/Documentation/admin-guide/mm/pagemap.rst
class PageMapReader:
    def __init__(self, pid = None):
        self.pagemap_fd_ = None 
        self.kpageflags_fd_ = open(KPAGEFLAGS_PATH, "rb")
        if pid is not None:
            self.connect(pid)

    def connect(self, pid):
        if self.pagemap_fd_ is not None:
            self.pagemap_fd_.close()
        self.pagemap_fd_ = open(PROCESS_PAGEMAP_PATH_TEMPLATE.format(pid), "rb")

    def getMapping(self, vpn):
        # read
        self.pagemap_fd_.seek(asClongCompatible(vpn * sizeof(PageMapEntry)))
        data = self.pagemap_fd_.read(sizeof(PageMapEntry))
        # parse
        pagemap_entry = PageMapEntry()
        pagemap_entry.unpack(data)
        # get kpageflags - if present 
        kpageflags = 0 
        if pagemap_entry.present:
            self.kpageflags_fd_.seek(asClongCompatible(pagemap_entry.pfn_swap * 8))
            kpageflags = int.from_bytes(self.kpageflags_fd_.read(8), "little")
        return (pagemap_entry, kpageflags)

    def __del__(self):
        if self.pagemap_fd_ is not None:
            self.pagemap_fd_.close()


class MemReader:
    def __init__(self, pid = None):
        self.mem_fd_ = None 
        if pid is not None:
            self.connect(pid)

    def connect(self, pid):
        if self.mem_fd_ is not None:
            self.mem_fd_.close()
        self.mem_fd_ = open(PROCESS_MEM_PATH_TEMPLATE.format(pid), "rb")

    def getMem(self, vaddr, size):
        self.mem_fd_.seek(asClongCompatible(vaddr))
        data = self.mem_fd_.read(size)
        return data

    def __del__(self):
        if self.mem_fd_ is not None:
            self.mem_fd_.close()


class HexDumpPrinter:
    def __init__(self, bytes_per_line, show_addr):
        self.bytes_per_line_ = bytes_per_line
        self.show_addr_ = show_addr

    def getPrintableAscii(self, byte):
        # printable range
        if byte >= 33 and byte <= 126:
            return chr(byte)
        # placeholder
        else:
            return '.'

    def print(self, data):
        offset = 0
        ascii_str = ""
        for byte in data:
            # new line
            if offset % self.bytes_per_line_ == 0:
                # print as hex string
                print(" " + ascii_str)
                if self.show_addr_:
                    print("0x{:08x}: ".format(offset), end="")
                ascii_str = ""

            # print byte
            print("{:02x} ".format(byte), end="")
            # add to string
            ascii_str += self.getPrintableAscii(byte)
            offset += 1
        # print left hexstring
        print(" " + ascii_str)


class PageUsageTracker:
    def __init__(self):
        self.page_idle_bitmap_fd_ = open(PAGE_IDLE_BITMAP_PATH, "r+b")

    def resetPfns(self, pfns):
        for pfn in pfns:
            if pfn == -1:
                continue
            # TODO might make problems
            self.page_idle_bitmap_fd_.seek(asClongCompatible(int(pfn / 64) * 8))
            # reset page (mark idle)
            self.page_idle_bitmap_fd_.write((1 << (pfn % 64)).to_bytes(8, "little"))

    def getPfnsState(self, pfns):
        states = []
        for pfn in pfns:
            if pfn == -1:
                states.append(0)
                continue
            # TODO might make problems
            self.page_idle_bitmap_fd_.seek(asClongCompatible(int(pfn / 64) * 8))
            # read state
            raw = self.page_idle_bitmap_fd_.read(8)
            number = int.from_bytes(raw, "little")
            # check if page was accessed (not idle anymore)
            states.append(not ((number >> (pfn % 64)) & 1))
        return states

    def __del__(self):
        if self.page_idle_bitmap_fd_ is not None:
            self.page_idle_bitmap_fd_.close()