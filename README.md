# Disk Cache Attacks
This repository contains several POCs, demonstrating the exploitation of the disk cache in Linux and Windows. For more background information refer to the paper:
  * [Page Cache Attacks](https://gruss.cc/files/pagecacheattacks.pdf) by Gruss, Kraft, Tiwari, Schwarz, Trachtenberg and Hennessey.

# Under Construction
Currently only the POC for the Linux side channel is online, the rest will follow soon.

# Preparations
## System
Most of the POCs have been designed and tested under the precondition that **swapping is disabled** and that they are run from a **SSD**. Although they might also work in other cases this will lead to a **worse performance** (swapping enabled, no SSD) and a high amount of disk writes (swapping enabled) which may increase **wearing out** your disk. To disable swapping follow these instructions:
  * Linux  
    * Temporarly  
      Run `swapoff -a` with root privileges. 
    * Permanent  
      Remove all swap entries from `/etc/fstab` and reboot.  
      
    You can use `cat /proc/swaps` to verify that there is no active swap area anymore.
 
## Note on Countermeasures
### Linux
<!---
    git tag --contains 134fca9063ad4851de767d1768180e5dede9a881
-->
Recent kernel versions (>= 5.2) include a countermeasure against the attack which only reveals valid information if the process has write access to the targeted file (see also [Patch](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=134fca9063ad4851de767d1768180e5dede9a881)). Therefore to confirm the POCs function you have to use a unpatched kernel version. If you are only interested in the performance of the attack you might also just use files you have write access to or run the POC as root.
 
# POCs
## Linux Side-Channel Attack (linux/evict_and_check)
### Building
Running `cmake . && make` should do the job.
### Running
**Note:** During the first run the POC will create a new file with a size equal to the amount of installed physical memory so make sure you have enough disk space available.  

**Usage**  
```
  Usage: ./ev_chk [target file] [page to watch] <-s> <-e executable> <-t file>
  
   [target file]
       The shared file which contains the page to which accesses
       should be monitored.
  
   [page to watch] 
       The file offset in pages of the target page.
  
   -s (optional)
       Collects statistics about eviction attempts as csv. 
       (accessed eviction memory -> "histogram_mem.csv", 
       eviction runtime -> "histogram_time.csv") 
 
   -e executable (optional) 
       Allows to specify an executable which is signaled in case of 
       an detected event (SIGUSR1).
  
   -t file (optional)
       Collects information about detected events as csv.
       (count, timestamp, eviction runtime, accessed eviction memory)
```  
To exit the POC press CTRL+C.
### Example
As an simple example, which also works on patched kernels, follow these instructions:
1. Build `linux/tools/access` using `cmake . && make`.   
   This tool can be used to simulate a simple access pattern with a configurable delay to a given file page.
2. Build the POC as described above.
3. Create a test file, for example by using `dd if=/dev/urandom of=./test.so bs=4k count=32`.
4. Launch the POC on page 1 of test.so `./ev_chk <path to test.so> 1` and wait until the POC is initialised ([OK] Ready).
5. Launch the access tool on the target page `./access <path to test.so> 1 1000 10` (1000ms period, 10 accesses in total).  
Now you should see the page accesses appearing in the output of the POC. On a system featuring a AMD Ryzen 5 2600X CPU, 16GB of Corsair DDR4 3000MHz RAM, a Samsung 970 EVO SSD and Linux 5.3.0-51 this leads to eviction times around 100ms. 

### Tweaking
Currently the attack is configured with defines starting at `linux\evict_and_check\src\main.c:131` you might want to play with these values to optimise the attack for your system.
