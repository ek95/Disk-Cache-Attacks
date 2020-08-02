#include "pageflags.h"
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>


// TODO maybe add select to prevent stalls
int openPageFlagsFd(PageFlagsFd *pageflags_fd)
{
    char pagemap_path[MAX_PAGEMAP_PATH_LEN] = {0};

    if(snprintf(pagemap_path, MAX_PAGEMAP_PATH_LEN, PAGEMAP_PATH_TEMPLATE, getpid()) > MAX_PAGEMAP_PATH_LEN)
    {
        return -1;
    }

    pageflags_fd->pagemap_fd_ = open(pagemap_path, O_RDONLY);
    if(pageflags_fd->pagemap_fd_ < 0)
    {
		pageflags_fd->pagemap_fd_ = -1;
        return -1;
    }

    pageflags_fd->kpageflags_fd_ = open(KPAGEFLAGS, O_RDONLY);
    if(pageflags_fd->kpageflags_fd_ < 0)
    {
		pageflags_fd->kpageflags_fd_ = -1;
        close(pageflags_fd->pagemap_fd_);
        return -1;
    }

    return 0;
}


void closePageFlagsFd(PageFlagsFd *pageflags_fd)
{
	if(pageflags_fd->kpageflags_fd_ >= 0)
	{
		close(pageflags_fd->kpageflags_fd_);
	}
	if(pageflags_fd->pagemap_fd_ >= 0)
	{
		close(pageflags_fd->pagemap_fd_);
	}
}


int getPagemapEntryVpn(PageFlagsFd *pageflags_fd, PageMapEntry *entry, size_t vpn)
{
    ssize_t return_value;
    size_t bytes_read;

    bytes_read = 0;
    do
    {
        return_value = pread(pageflags_fd->pagemap_fd_, entry + bytes_read, sizeof(PageMapEntry) - bytes_read, vpn * sizeof(PageMapEntry) + bytes_read);
        if(return_value < 0)
        {
            return -1;
        }
        bytes_read += return_value;
    }
    while(bytes_read < sizeof(PageMapEntry));

    return 0;
}


int getKPageFlagsEntryPfn(PageFlagsFd *pageflags_fd, KPageFlagsEntry *entry, size_t pfn)
{
    ssize_t return_value;
    size_t bytes_read;

    bytes_read = 0;
    do
    {
        return_value = pread(pageflags_fd->kpageflags_fd_, entry + bytes_read, sizeof(KPageFlagsEntry) - bytes_read, pfn * sizeof(KPageFlagsEntry) + bytes_read);
        if(return_value < 0)
        {
            return -1;
        }
        bytes_read += return_value;
    }
    while(bytes_read < sizeof(KPageFlagsEntry));

    return 0;
}


int getKPageFlagsEntryVpn(PageFlagsFd *pageflags_fd, KPageFlagsEntry *page_flags, size_t vpn)
{
    PageMapEntry pme = {0};

    if(getPagemapEntryVpn(pageflags_fd, &pme, vpn) != 0 || !pme.present)
    {
		errno = EFAULT;
        return -1;
    }

    return getKPageFlagsEntryPfn(pageflags_fd, page_flags, pme.present_swap.present_info.pfn);
}
