#ifndef BASE_H
#define BASE_H

#include<stdio.h>
#include<unistd.h>
#include<stddef.h>
#include<pthread.h> // -lpthread
#include "align.h"


#define NBINS             128 
#define NSMALLBINS         64
#define FASTBIN_CONSOLIDATION_THRESHOLD (65536UL)
#define SMALLBIN_WIDTH    (MALLOC_ALIGNMENT)
#define MIN_LARGE_SIZE    (NSMALLBINS * SMALLBIN_WIDTH) 

#define NFASTBINS        10
#define BINMAPSHIFT      5  
#define BITSPERMAP       (1U << BINMAPSHIFT)
#define BINMAPSIZE       (NBINS / BITSPERMAP) 

/* mutex */
typedef pthread_mutex_t mutex_t;

#define MUTEX_INITIALIZER          PTHREAD_MUTEX_INITIALIZER
#define mutex_init(m)              pthread_mutex_init(m, NULL)
#define mutex_lock(m)              pthread_mutex_lock(m)
#define mutex_trylock(m)           pthread_mutex_trylock(m)
#define mutex_unlock(m)            pthread_mutex_unlock(m)
//线程变量
typedef pthread_key_t tsd_key_t;
#define tsd_key_create(key, destr) pthread_key_create(key, destr)
#define tsd_setspecific(key, data) pthread_setspecific(key, data)
#define tsd_getspecific(key, vptr) (vptr = pthread_getspecific(key))

#define HEAP_MAX_SIZE (64*1024*1024)



typedef struct malloc_chunk
{
	INTERNAL_SIZE_T prev_size; /* Size of previous chunk (if free). */
	INTERNAL_SIZE_T size;      /* Size in bytes, including overhead. */
	struct malloc_chunk* fd;   /* double links -- used only if free. */
	struct malloc_chunk* bk;
	//struct malloc_chunk* lf; /*left child*/
	//struct malloc_chunk* rt; /*right child*/
	//struct malloc_chunk* parent; /*father chunk*/
	/* Only used for large blocks: pointer to next larger size.  */
  /* 只在large块时使用：指向下一个更大大小的指针 */
	struct malloc_chunk* fd_nextsize; /* double links -- used only if free. */
	struct malloc_chunk* bk_nextsize;
}malloc_chunk;
typedef malloc_chunk* mchunkptr;
typedef malloc_chunk* mbinptr, * mfastbinptr;

#define FROM_SPLIT 3
#define FROM_OLD_CHUNK 4
#define FROM_MMAP 5
typedef struct mm_info {
	void* mm_ptr;
	int type;
	malloc_chunk *remainder_ptr;
}mm_info;

typedef struct treeNode {
	treeNode* lf;
	treeNode* rt;
	mchunkptr chunk;
	char wait_free;
} treeNode;
typedef treeNode* treeNodePtr;

typedef struct malloc_state
{
	mutex_t mutex;
	int flags;
	mfastbinptr fastbinsY[NFASTBINS];
	mchunkptr top;
	mchunkptr last_remainder;
	mchunkptr bins[NBINS * 2 - 2];
	treeNode treetop;
	unsigned int binmap[BINMAPSIZE];
	malloc_state* next;
	malloc_state* next_free;
	/* Memory allocated from the system in this arena.  */
	INTERNAL_SIZE_T system_mem;   
	INTERNAL_SIZE_T max_system_mem;
}malloc_state;
typedef malloc_state *mstate;

typedef struct malloc_par {
	unsigned long trim_threshold;
	INTERNAL_SIZE_T top_pad;
	INTERNAL_SIZE_T mmap_threshold;
	INTERNAL_SIZE_T arena_test; //小于这个阈值如果有锁直接建新的arean
	INTERNAL_SIZE_T arena_max; //最大分配区个数
	 /* Memory map support */
	int n_mmaps;
	int n_mmaps_max;
	int max_n_mmaps;
	/* the mmap_threshold is dynamic, until the user sets
	  it manually, at which point we need to disable any
	  dynamic behavior. */
	int no_dyn_threshold;

	/* Cache malloc_getpagesize */
	unsigned int pagesize;
	/* Statistics */
	INTERNAL_SIZE_T  mmapped_mem;
	INTERNAL_SIZE_T  max_mmapped_mem;
	/* First address handed out by MORECORE/sbrk.  */
	char* sbrk_base;

}malloc_par;

#define NONCONTIGUOUS_BIT     (2U) 
#define contiguous(M)          (((M)->flags &  NONCONTIGUOUS_BIT) == 0) 
#define noncontiguous(M)       (((M)->flags &  NONCONTIGUOUS_BIT) != 0) 
#define set_noncontiguous(M)   ((M)->flags |=  NONCONTIGUOUS_BIT) 
#define set_contiguous(M)      ((M)->flags &= ~NONCONTIGUOUS_BIT)


typedef struct _heap_info {
	mstate ar_ptr; /* Arena for this heap. */
	struct _heap_info* prev; /* Previous heap. */
	size_t size;   /* Current size in bytes. */
	size_t mprotect_size; /* Size in bytes that has been mprotected
								  PROT_READ|PROT_WRITE.  */
								  /* Make sure the following data is properly aligned, particularly
									 that sizeof (heap_info) + 2 * SIZE_SZ is a multiple of
									 MALLOC_ALIGNMENT. */
	char pad[-6 * SIZE_SZ & MALLOC_ALIGN_MASK];
} heap_info;
typedef heap_info* heap_info_ptr;

#endif // !BASE_H



