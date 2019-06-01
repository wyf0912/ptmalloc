#ifndef BINS_H
#define BINS_H
#include "align.h"
#include "base.h"

#define largebin_index_64(sz)                                                 \
 (((((unsigned long)(sz)) >>  6) <= 48)?  48 + (((unsigned long)(sz)) >>  6): \
((((unsigned long)(sz)) >> 9) <= 20) ? 91 + (((unsigned long)(sz)) >> 9) :    \
((((unsigned long)(sz)) >> 12) <= 10) ? 110 + (((unsigned long)(sz)) >> 12) : \
((((unsigned long)(sz)) >> 15) <= 4) ? 119 + (((unsigned long)(sz)) >> 15) :  \
((((unsigned long)(sz)) >> 18) <= 2) ? 124 + (((unsigned long)(sz)) >> 18) :  \
126)

mbinptr bin_at(mstate m, int i);
void malloc_unlink(mchunkptr P, mchunkptr BK, mchunkptr FD);
//mbinptr top(a)
/* addressing -- note that bin_at(0) does not exist */

//#define bin_at(m, i) (mbinptr) (((char *) &((m)->bins[((i) - 1) * 2])) - offsetof (struct malloc_chunk, fd)) 
#define top(a) (bin_at(a,0)->fd) 
#define first(b) ((b)->fd)
#define last(b)  ((b)->bk)
#define in_smallbin_range(sz) ((unsigned long)(sz) < (unsigned long)MIN_LARGE_SIZE) 
#define smallbin_index(sz) (((unsigned)(sz)) >> 4) 

#define largebin_index(sz) (largebin_index_64 (sz)) 

#define bin_index(sz) ((in_smallbin_range(sz)) ? smallbin_index(sz) : largebin_index(sz)) 

#define next_bin(b)  ((mbinptr)((char*)(b) + (sizeof(mchunkptr)<<1)))
#define fastbin(ar_ptr, idx) ((ar_ptr)->fastbinsY[idx])
/* offset 2 to use otherwise unindexable first 2 bins */
#define MAX_FAST_SIZE (80 * SIZE_SZ / 4)
#define fastbin_index(sz) ((((unsigned int)(sz)) >> (SIZE_SZ == 8 ? 4 : 3)) - 2)
/* The maximum fastbin request size we support */

#define unsorted_chunks(M) (bin_at(M, 1))
#define initial_top(M) (unsorted_chunks(M)) 
#endif // !BINS_H
