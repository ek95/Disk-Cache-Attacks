# Disk Cache Attacks
This repository contains several POCs, demonstrating the exploitation of the disk cache in Linux and Windows. For more background information refer to the paper:
  * [Page Cache Attacks](https://gruss.cc/files/pagecacheattacks.pdf) by Gruss, Kraft, Tiwari, Schwarz, Trachtenberg and Hennessey.

# Under Construction
Currently only the POC for the Linux side channel is online, the rest will follow soon.

# Preparations
## System
Most of the POCs have been designed and tested under the precondition that **swapping is disabled** and that they are run from a **SSD**. Although they might also work in other cases this will lead to a **worse performance** (swapping enabled, no SSD) and a high amount of disk writes (swapping enabled) which may increase **wearing out** your disk. To disable swapping follow this instructions:
  * Linux  
    * Temporarly  
      Run `swapoff -a` with root privileges. 
    * Permanent  
      Remove all swap entries from `/etc/fstab` and reboot.  
      
    You can use `cat  /proc/swaps` to verify there is no active swap area anymore.
 
## Note on Countermeasures
### Linux
Recent kernel versions include a countermeasure against the attack which only reveals valid information if the process has write access to the targeted file (see also [Patch](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=134fca9063ad4851de767d1768180e5dede9a881)). Therefore to conform the POCs function you have to use an unpatched kernel version. If you are only interested in the performance of the attack you migh also just use files you have write access to or run the POC as root.
 
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


### Tweaking
Currently the attack is configured with defines starting at `linux\evict_and_check\src\main.c:130` you might want to play with these values to optimise the attack for your system.
