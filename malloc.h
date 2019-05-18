#ifndef MALLOC_H
#define MALLOC_H
#include "flagopt.h"
#include "align.h"
#include "bins.h"
#include "base.h"
#include <fcntl.h>
#include <sys/mman.h>

static mutex_t list_lock;
static malloc_state main_arena;
static malloc_par mp_; 
static int global_max_fast;


void* malloc(size_t n);
void free(void* ptr);

#define MAX_AREAN_NUM 10
#define HEAP_MIN_SIZE (32*1024)
#define malloc_getpagesize sysconf(_SC_PAGE_SIZE)
#define MAP_FAILED ((char*)-1)


static int dev_zero_fd = -1; /* Cached file descriptor for /dev/zero. */
#define MMAP(addr, size, prot, flags) ((dev_zero_fd < 0) ? \
 (dev_zero_fd = open("/dev/zero", O_RDWR), \
  mmap((addr), (size), (prot), (flags), dev_zero_fd, 0)) : \
   mmap((addr), (size), (prot), (flags), dev_zero_fd, 0))

static int arean_num = 0;
#endif // !MALLOC_H

