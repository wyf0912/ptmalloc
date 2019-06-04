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

mm_info _malloc(int n);
void* malloc(int n);
void* simple_malloc(int bytes);
void free(void* ptr);
#define arena_for_chunk(ptr) \
 (chunk_non_main_arena(ptr) ? heap_for_ptr(ptr)->ar_ptr : &main_arena)
#define DEFAULT_MMAP_THRESHOLD (128 * 1024)
#define DEFAULT_TRIM_THRESHOLD (128 * 1024)
#define DEFAULT_MMAP_THRESHOLD_MAX (4 * 1024 * 1024 * sizeof(long))
#define DEFAULT_MMAP_MAX 65536
#define HEAP_MIN_SIZE (32*1024)
#define malloc_getpagesize sysconf(_SC_PAGE_SIZE)
#ifdef  MAP_FAILED
#undef MAP_FAILED
#define MAP_FAILED ((char*)-1)
#endif // ! MAP_FAILED
#define MORECORE_FAILURE -1
#define DEFAULT_MAXFAST 128
#define MMAP_AS_MORECORE_SIZE (1024 * 1024)
#define set_max_fast(s) (global_max_fast = (((s) == 0)   ? SMALLBIN_WIDTH: ((s + SIZE_SZ) & ~MALLOC_ALIGN_MASK)))
#define get_max_fast() (global_max_fast)
#define heap_for_ptr(ptr) \
 ((heap_info *)((unsigned long)(ptr) & ~(HEAP_MAX_SIZE-1)))

typedef pthread_t thread_id;

static mstate arean_get2(size_t size);
static heap_info_ptr new_heap(size_t size, size_t top_pad);
static void malloc_init_state(mstate av);
static mm_info sYSMALLOc(INTERNAL_SIZE_T nb, mstate av);
static int grow_heap(heap_info* h, long diff);
static void _int_free(mstate av, mchunkptr p);
static void ptmalloc_init_minimal();
static void ptmalloc_lock_all();
static void ptmalloc_unlock_all();
static void ptmalloc_unlock_all2();
static int shrink_heap(heap_info* h, long diff);
static int heap_trim(heap_info* heap, size_t pad);
static int sYSTRIm(size_t pad, mstate av);
static void munmap_chunk(mchunkptr p);
static int dev_zero_fd = -1; /* Cached file descriptor for /dev/zero. */
/* Mapped memory in non-main arenas (reliable only for NO_THREADS). */
static unsigned long arena_mem;
#define MMAP(addr, size, prot, flags) ((dev_zero_fd < 0) ? \
 (dev_zero_fd = open("/dev/zero", O_RDWR), \
  mmap((addr), (size), (prot), (flags), dev_zero_fd, 0)) : \
   mmap((addr), (size), (prot), (flags), dev_zero_fd, 0))

/*
  Binmap

	To help compensate for the large number of bins, a one-level index
	structure is used for bin-by-bin searching.  `binmap' is a
	bitvector recording whether bins are definitely empty so they can
	be skipped over during during traversals.  The bits are NOT always
	cleared as soon as bins are empty, but instead only
	when they are noticed to be empty during traversal in malloc.
*/

/* Conservatively use 32 bits per map word, even if on 64bit system */
#define BINMAPSHIFT      5
#define BITSPERMAP       (1U << BINMAPSHIFT)
#define BINMAPSIZE       (NBINS / BITSPERMAP)

#define idx2block(i)     ((i) >> BINMAPSHIFT)
#define idx2bit(i)       ((1U << ((i) & ((1U << BINMAPSHIFT)-1))))

#define mark_bin(m,i)    ((m)->binmap[idx2block(i)] |=  idx2bit(i))
#define unmark_bin(m,i)  ((m)->binmap[idx2block(i)] &= ~(idx2bit(i)))
#define get_binmap(m,i)  ((m)->binmap[idx2block(i)] &   idx2bit(i))

#define delete_heap(heap) \
  do {								\
    if ((char *)(heap) + HEAP_MAX_SIZE == aligned_heap_area)	\
      aligned_heap_area = NULL;					\
    munmap((char*)(heap), HEAP_MAX_SIZE);			\
  } while (0)

#endif // !MALLOC_H

