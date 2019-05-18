#ifndef BASE_H
#define BASE_H

#include<stdio.h>
#include<unistd.h>
#include<stddef.h>
#include<pthread.h> // -lpthread
#include "align.h"


#define NBINS             128 
#define NSMALLBINS         64 
#define SMALLBIN_WIDTH    (MALLOC_ALIGNMENT)
#define MIN_LARGE_SIZE    (NSMALLBINS * SMALLBIN_WIDTH) 

#define NFASTBINS        10
#define BINMAPSHIFT      5  
#define BITSPERMAP       (1U << BINMAPSHIFT)
#define BINMAPSIZE       (NBINS / BITSPERMAP) 
/* Conservatively use 32 bits per map word, even if on 64bit system */




typedef pthread_mutex_t mutex_t;

#define HEAP_MAX_SIZE (64*1024*1024)

typedef struct malloc_chunk
{
	INTERNAL_SIZE_T prev_size; /* Size of previous chunk (if free). */
	INTERNAL_SIZE_T size;      /* Size in bytes, including overhead. */
	struct malloc_chunk* fd;   /* double links -- used only if free. */
	struct malloc_chunk* bk;
	/* Only used for large blocks: pointer to next larger size.  */
  /* 只在large块时使用：指向下一个更大大小的指针 */
	struct malloc_chunk* fd_nextsize; /* double links -- used only if free. */
	struct malloc_chunk* bk_nextsize;
}malloc_chunk;
typedef malloc_chunk* mchunkptr;
typedef malloc_chunk* mbinptr, * mfastbinptr;

typedef struct malloc_state
{
	mutex_t mutex;
	int flags;
	mfastbinptr fastbinsY[NFASTBINS];
	mchunkptr top;
	mchunkptr last_remainder;
	mchunkptr bins[NBINS * 2 - 2];
	unsigned int binmap[BINMAPSIZE];
	malloc_state* next;
}malloc_state;
typedef malloc_state *mstate;

typedef struct malloc_par {

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



