#pragma once
#ifndef FLAGOPT_H
#define FLAGOPT_H

#define PREV_INUSE 0x1 /* extract inuse bit of previous chunk */
#define prev_inuse(p)       ((p)->size & PREV_INUSE) 
#define IS_MMAPPED 0x2 /* check for mmap()'ed chunk */
#define chunk_is_mmapped(p) ((p)->size & IS_MMAPPED) 
#define NON_MAIN_ARENA 0x4 
#define chunk_non_main_arena(p) ((p)->size & NON_MAIN_ARENA) 

#define inuse_bit_at_offset(p, s)\  (((mchunkptr)(((char*)(p)) + (s)))->size & PREV_INUSE) 
#define set_inuse_bit_at_offset(p, s)\  (((mchunkptr)(((char*)(p)) + (s)))->size |= PREV_INUSE) 
#define clear_inuse_bit_at_offset(p, s)\  (((mchunkptr)(((char*)(p)) + (s)))->size &= ~(PREV_INUSE)

/* Set size at head, without disturbing its use bit */
#define set_head_size(p, s)  ((p)->size = (((p)->size & SIZE_BITS) | (s))) /* Set size/use field */
#define set_head(p, s)       ((p)->size = (s)) /* Set size at footer (only when chunk is not in use) */
#define set_foot(p, s)       (((mchunkptr)((char*)(p) + (s)))->prev_size = (s))

#define SIZE_BITS (PREV_INUSE|IS_MMAPPED|NON_MAIN_ARENA)
#define chunksize(p)         ((p)->size & ~(SIZE_BITS)) 
#define next_chunk(p) ((mchunkptr)( ((char*)(p)) + ((p)->size & ~SIZE_BITS) )) /* Ptr to previous physical malloc_chunk */
#define prev_chunk(p) ((mchunkptr)( ((char*)(p)) - ((p)->prev_size) )) /* Treat space at ptr + offset as a chunk */
#define chunk_at_offset(p, s)  ((mchunkptr)(((char*)(p)) + (s)))	
#endif // !FLAGOPT_H

