#ifndef MALLOC_H
#define MALLOC_H
#include "flagopt.h"
#include "align.h"
#include "bins.h"
#include "base.h"
#include <pthread.h>
#include <fcntl.h>
#include <sys/mman.h>

static mstate free_list;
static mutex_t list_lock;
static malloc_state main_arena;
static void* save_arena;
static tsd_key_t arena_key;
static malloc_par mp_; 
static int global_max_fast;
static int nareans=0;
static int __malloc_initialized = 0;

void* malloc(size_t n);
void free(void* ptr);

#define DEFAULT_MMAP_THRESHOLD (128 * 1024)
#define DEFAULT_TRIM_THRESHOLD (128 * 1024)
#define HEAP_MIN_SIZE (32*1024)
#define malloc_getpagesize sysconf(_SC_PAGE_SIZE)
#ifdef  MAP_FAILED
#undef MAP_FAILED
#define MAP_FAILED ((char*)-1)
#endif // ! MAP_FAILED
#define DEFAULT_MAXFAST 10
#define set_max_fast(s) (global_max_fast = (((s) == 0)   ? SMALLBIN_WIDTH: ((s + SIZE_SZ) & ~MALLOC_ALIGN_MASK)))
#define get_max_fast() (global_max_fast)

typedef pthread_t thread_id;

static mstate arean_get2(size_t size);
static heap_info_ptr new_heap(size_t size, size_t top_pad);
static void malloc_init_state(mstate av);
static void ptmalloc_init_minimal();
static void ptmalloc_lock_all();
static void ptmalloc_unlock_all();
static void ptmalloc_unlock_all2();
static int dev_zero_fd = -1; /* Cached file descriptor for /dev/zero. */
#define MMAP(addr, size, prot, flags) ((dev_zero_fd < 0) ? \
 (dev_zero_fd = open("/dev/zero", O_RDWR), \
  mmap((addr), (size), (prot), (flags), dev_zero_fd, 0)) : \
   mmap((addr), (size), (prot), (flags), dev_zero_fd, 0))

#endif // !MALLOC_H

