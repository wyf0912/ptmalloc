#include "malloc.h"
#include <cerrno>
#include <unistd.h>
#include "bins.h"
#include <pthread.h>
#include <assert.h>
#include <stdint.h>

#define DEBUG
#define FASTCHUNKS_BIT        (1U)
#define clear_fastchunks(M)    ((M)->flags |=  FASTCHUNKS_BIT)
#define set_fastchunks(M)      ((M)->flags &= ~FASTCHUNKS_BIT)
#define inuse_bit_at_offset(p, s)\
 (((mchunkptr)(((char*)(p)) + (s)))->size & PREV_INUSE)

#define set_inuse_bit_at_offset(p, s)\
 (((mchunkptr)(((char*)(p)) + (s)))->size |= PREV_INUSE)

#define clear_inuse_bit_at_offset(p, s)\
 (((mchunkptr)(((char*)(p)) + (s)))->size &= ~(PREV_INUSE))
#define check_malloc_state(A)
#define have_fastchunks(M)     (((M)->flags &  FASTCHUNKS_BIT) == 0)

static mstate get_free_list() {
	mstate result = free_list;
	if (result != NULL) {
		(void)pthread_mutex_lock(&list_lock);
		result = free_list;
		if (result != NULL)
			free_list = result->next_free;
		(void)pthread_mutex_lock(&list_lock);
		if (result != NULL)
		{
			(void)pthread_mutex_lock(&result->mutex);
			tsd_setspecific(arena_key, (void*)result);
		}
	}
	return result;
}
static mstate reused_arena() {
	if (nareans <= mp_.arena_max)
		return NULL;
	mstate result;
	static mstate next_to_use;
	if (next_to_use == NULL)
		next_to_use = &main_arena;
	result = next_to_use;
	do {
		if (!pthread_mutex_trylock(&result->mutex))
			goto out;
		result = result->next;
	} while (result != next_to_use); //环形链表
	pthread_mutex_lock(&result->mutex);
out:tsd_setspecific(arena_key, (void*)result);
	next_to_use = result->next;
	return result;
}

static mstate arena_lookup() {
	return (mstate)pthread_getspecific(arena_key);
}

static mstate arena_lock(mstate ptr, unsigned int size) {
	if (ptr && !mutex_trylock(&ptr->mutex));
	else
		ptr = arean_get2(size);
	return ptr;
}
static mstate arean_get(unsigned int size) {
	mstate ptr;
	ptr = arena_lookup();
	ptr = arena_lock(ptr, size);
	return ptr;
}

static mstate new_arena(size_t size) {
	mstate a;
	heap_info_ptr h;
	char* ptr;
	unsigned long misalign;
	h = new_heap(size + (sizeof(*h) + sizeof(*a) + MALLOC_ALIGNMENT), mp_.top_pad);
	if (!h) {     
		h = new_heap(sizeof(*h) + sizeof(*a) + MALLOC_ALIGNMENT, mp_.top_pad);    
		if (!h)       
			return 0;
	}
	a = h->ar_ptr = (mstate)(h + 1);   
	malloc_init_state(a);   /*a - >next = NULL;*/
	a->system_mem = a->max_system_mem = h->size;   
	//arena_mem += h->size;
	ptr = (char*)(a + 1);   
	misalign = (unsigned long)chunk2mem(ptr) & MALLOC_ALIGN_MASK;   
	if (misalign > 0)     
		ptr += MALLOC_ALIGNMENT - misalign;   
	top(a) = (mchunkptr)ptr;
	set_head(top(a), (((char*)h + h->size) - ptr) | PREV_INUSE);
	tsd_setspecific(arena_key, (void*)a);   
	mutex_init(&a->mutex); 
	(void)pthread_mutex_lock(&a->mutex);
	(void)pthread_mutex_lock(&list_lock);
	/* Add the new arena to the global list.  */
	a->next = main_arena.next;
	//atomic_write_barrier();
	main_arena.next = a;
	++nareans;
	(void)pthread_mutex_unlock(&list_lock);
	return a;
};

static mstate arean_get2(size_t size) {
	mstate a;
	//if ((a = get_free_list()) == NULL && (a = reused_arena()) == NULL)
		a = new_arena(size);
	return a;
}

static void malloc_consolidate(mstate av)
{
	mfastbinptr* fb;                 /* current fastbin being consolidated */
	mfastbinptr* maxfb;              /* last fastbin (for loop control) */
	mchunkptr       p;                  /* current chunk being consolidated */
	mchunkptr       nextp;              /* next chunk to consolidate */
	mchunkptr       unsorted_bin;       /* bin header */
	mchunkptr       first_unsorted;     /* chunk to link to */

	/* These have same use as in free() */
	mchunkptr       nextchunk;
	INTERNAL_SIZE_T size;
	INTERNAL_SIZE_T nextsize;
	INTERNAL_SIZE_T prevsize;
	int             nextinuse;
	mchunkptr       bck;
	mchunkptr       fwd;
	if (get_max_fast() != 0) {
		clear_fastchunks(av);

		unsorted_bin = unsorted_chunks(av);

		/*
		  Remove each chunk from fast bin and consolidate it, placing it
		  then in unsorted bin. Among other reasons for doing this,
		  placing in unsorted bin avoids needing to calculate actual bins
		  until malloc is sure that chunks aren't immediately going to be
		  reused anyway.
		*/

		maxfb = &fastbin(av, NFASTBINS - 1);
		fb = &fastbin(av, 0);
		do {
			p = *fb;
			if (p != 0) {
				* fb = 0;
				do {
					//check_inuse_chunk(av, p);  //only be used in DEBUG MODE
					nextp = p->fd;

					/* Slightly streamlined version of consolidation code in free() */
					size = p->size & ~(PREV_INUSE | NON_MAIN_ARENA);
					nextchunk = chunk_at_offset(p, size);
					nextsize = chunksize(nextchunk);

					if (!prev_inuse(p)) {
						prevsize = p->prev_size;
						size += prevsize;
						p = chunk_at_offset(p, -((long)prevsize));
						malloc_unlink(p, bck, fwd);
					}

					if (nextchunk != av->top) {
						nextinuse = inuse_bit_at_offset(nextchunk, nextsize);

						if (!nextinuse) {
							size += nextsize;
							malloc_unlink(nextchunk, bck, fwd);
						}
						else
							clear_inuse_bit_at_offset(nextchunk, 0);
						//unsorted_bin = unsorted_chunks(av);//源代码的BUG? 不清零的话...内存泄漏
						first_unsorted = unsorted_bin->fd;
						unsorted_bin->fd = p;
						first_unsorted->bk = p;

						if (!in_smallbin_range(size)) {
							p->fd_nextsize = NULL;
							p->bk_nextsize = NULL;
						}

						set_head(p, size | PREV_INUSE);
						p->bk = unsorted_bin;
						p->fd = first_unsorted;
						set_foot(p, size);
					}

					else {
						size += nextsize;
						set_head(p, size | PREV_INUSE);
						av->top = p;
					}

				} while ((p = nextp) != 0);

			}
		} while (fb++ != maxfb);
	}
	else {
		malloc_init_state(av);
	}
}

mm_info _int_malloc(mstate av, size_t bytes) {
	INTERNAL_SIZE_T nb;               /* normalized request size */
	unsigned int    idx;              /* associated bin index */
	mbinptr         bin;              /* associated bin */
	mchunkptr       victim;           /* inspected/selected chunk */
	INTERNAL_SIZE_T size;             /* its size */
	int             victim_index;     /* its bin index */
	mchunkptr       remainder;        /* remainder from a split */
	unsigned long   remainder_size;   /* its size */
	unsigned int    block;            /* bit map traverser */
	unsigned int    bit;              /* bit map traverser */
	unsigned int    map;              /* current word of binmap */
	mchunkptr       fwd;              /* misc temp for linking */
	mchunkptr       bck;              /* misc temp for linking */
	const char* errstr = NULL;
	mm_info mm;
	mm.mm_ptr = NULL;
	nb = request2size(bytes);
	if ((unsigned long)(nb) <= (unsigned long)(get_max_fast())) {
		idx = fastbin_index(nb);
		mfastbinptr* fb = &fastbin(av, idx);
		victim = *fb;
		if (victim != 0) {
			if (__builtin_expect(fastbin_index(chunksize(victim)) != idx, 0))
			{
				printf("malloc(): memory corruption (fast)");
				return mm;
			}
			* fb = victim->fd;
			//check_remalloced_chunk(av, victim, nb);5
			void* p = chunk2mem(victim);
			mm.mm_ptr = p;
			mm.type = FROM_OLD_CHUNK;
			mm.remainder_ptr = victim;
			return mm;
		}
	}
	if (in_smallbin_range(nb)) {
		idx = smallbin_index(nb);     
		bin = bin_at(av, idx);
		if ((victim = last(bin)) != bin) {
			if (victim == 0) /* initialization check */
				malloc_consolidate(av);       
			else {
				bck = victim->bk;         
				if (__builtin_expect(bck->fd != victim, 0)) {
					printf("malloc(): smallbin double linked list corrupted");             
					return mm;
				}         
				set_inuse_bit_at_offset(victim, nb);         
				bin->bk = bck;         
				bck->fd = bin;
				if (av != &main_arena)           
					victim->size |= NON_MAIN_ARENA;       
					void* p = chunk2mem(victim);
					mm.mm_ptr = p;
					mm.type = FROM_OLD_CHUNK;
					mm.remainder_ptr = victim;
					return mm;
			}
		}
	}
	else {
		idx = largebin_index(nb);
		if (have_fastchunks(av))
			malloc_consolidate(av);
	}
	for (;;) {
		int iters = 0;
		while ((victim = unsorted_chunks(av)->bk) != unsorted_chunks(av)) {
			bck = victim->bk;
			if (__builtin_expect(victim->size <= 2 * SIZE_SZ, 0)
				|| __builtin_expect(victim->size > av->system_mem, 0))
				printf( "malloc(%d): memory corruption",chunk2mem(victim));
			size = chunksize(victim);

			/*
		   If a small request, try to use last remainder if it is the
		   only chunk in unsorted bin.  
			*/
			if (in_smallbin_range(nb) &&
				bck == unsorted_chunks(av) &&
				victim == av->last_remainder &&
				(unsigned long)(size) > (unsigned long)(nb + MINSIZE)) {

				/* split and reattach remainder */
				mm.type = FROM_SPLIT;
				remainder_size = size - nb;
				remainder = chunk_at_offset(victim, nb);       
				mm.remainder_ptr = remainder;
				unsorted_chunks(av)->bk = unsorted_chunks(av)->fd = remainder;
				av->last_remainder = remainder;
				remainder->bk = remainder->fd = unsorted_chunks(av);
				if (!in_smallbin_range(remainder_size))
				{
					remainder->fd_nextsize = NULL;
					remainder->bk_nextsize = NULL;
				}
				set_head(victim, nb | PREV_INUSE |
					(av != &main_arena ? NON_MAIN_ARENA : 0));
				set_head(remainder, remainder_size | PREV_INUSE);
				set_foot(remainder, remainder_size);

				//check_malloced_chunk(av, victim, nb);
				void* p = chunk2mem(victim);
				mm.mm_ptr = p;
				return mm;
			}

			/* remove from unsorted list */
			unsorted_chunks(av)->bk = bck;
			bck->fd = unsorted_chunks(av);

			/* Take now instead of binning if exact fit */

			if (size == nb) {
				set_inuse_bit_at_offset(victim, size);
				if (av != &main_arena)
					victim->size |= NON_MAIN_ARENA;
				//check_malloced_chunk(av, victim, nb);
				mm.type = FROM_OLD_CHUNK;
				void* p = chunk2mem(victim);
				mm.mm_ptr = p;
				return mm;
			}

			/* place chunk in bin */

			if (in_smallbin_range(size)) {
				victim_index = smallbin_index(size);
				bck = bin_at(av, victim_index);
				fwd = bck->fd;
			}
			else {
				victim_index = largebin_index(size);
				bck = bin_at(av, victim_index);
				fwd = bck->fd;

				/* maintain large bins in sorted order */
				if (fwd != bck) {
					/* Or with inuse bit to speed comparisons */
					size |= PREV_INUSE;
					/* if smaller than smallest, bypass loop below */
					assert((bck->bk->size & NON_MAIN_ARENA) == 0);
					if ((unsigned long)(size) < (unsigned long)(bck->bk->size)) {
						fwd = bck;
						bck = bck->bk;

						victim->fd_nextsize = fwd->fd;
						victim->bk_nextsize = fwd->fd->bk_nextsize;
						fwd->fd->bk_nextsize = victim->bk_nextsize->fd_nextsize = victim;
					}
					else {
						while ((unsigned long)size < fwd->size)
						{
							fwd = fwd->fd_nextsize;
						}
						if ((unsigned long)size == (unsigned long)fwd->size)
							/* Always insert in the second position.  */
							fwd = fwd->fd;
						else
						{
							victim->fd_nextsize = fwd;
							victim->bk_nextsize = fwd->bk_nextsize;
							fwd->bk_nextsize = victim;
							victim->bk_nextsize->fd_nextsize = victim;
						}
						bck = fwd->bk;
					}
				}
				else
					victim->fd_nextsize = victim->bk_nextsize = victim;
			}

			mark_bin(av, victim_index);
			victim->bk = bck;
			victim->fd = fwd;
			fwd->bk = victim;
			bck->fd = victim;

			#define MAX_ITERS	10000
			if (++iters >= MAX_ITERS)
				break;
		}
		if (!in_smallbin_range(nb)) {
			bin = bin_at(av, idx);

			/* skip scan if empty or largest chunk is too small */
			if ((victim = first(bin)) != bin &&
				(unsigned long)(victim->size) >= (unsigned long)(nb)) {

				victim = victim->bk_nextsize;
				while (((unsigned long)(size = chunksize(victim)) <
					(unsigned long)(nb)))
					victim = victim->bk_nextsize;

				if (victim != last(bin) && victim->size == victim->fd->size)
					victim = victim->fd;

				remainder_size = size - nb;
				malloc_unlink(victim, bck, fwd);

				/* Exhaust */
				if (remainder_size < MINSIZE) {
					set_inuse_bit_at_offset(victim, size);
					if (av != &main_arena)
						victim->size |= NON_MAIN_ARENA;
				}
				/* Split */
				else {
					remainder = chunk_at_offset(victim, nb);
					/* We cannot assume the unsorted list is empty and therefore
					   have to perform a complete insert here.  */
					bck = unsorted_chunks(av);
					mm.type = FROM_SPLIT;
					mm.remainder_ptr = remainder;
					fwd = bck->fd;
					if (__builtin_expect(fwd->bk != bck, 0))
					{
						printf("malloc(): corrupted unsorted chunks");
						return mm;
					}
					remainder->bk = bck;
					remainder->fd = fwd;
					bck->fd = remainder;
					fwd->bk = remainder;
					if (!in_smallbin_range(remainder_size))
					{
						remainder->fd_nextsize = NULL;
						remainder->bk_nextsize = NULL;
					}
					set_head(victim, nb | PREV_INUSE |
						(av != &main_arena ? NON_MAIN_ARENA : 0));
					set_head(remainder, remainder_size | PREV_INUSE);
					set_foot(remainder, remainder_size);
				}
				//check_malloced_chunk(av, victim, nb);
				void* p = chunk2mem(victim);
				mm.mm_ptr = p;
				return mm;
			}
		}

		//从BINS里面寻找一个chunk
		++idx;
		bin = bin_at(av, idx);
		block = idx2block(idx);
		map = av->binmap[block];
		bit = idx2bit(idx);

		for (;;) {
			/* Skip rest of block if there are no more set bits in this block.  */
			if (bit > map || bit == 0) {
				do {
					if (++block >= BINMAPSIZE)  /* out of bins */
						goto use_top;
				} while ((map = av->binmap[block]) == 0);

				bin = bin_at(av, (block << BINMAPSHIFT));
				bit = 1;
			}

			/* Advance to bin with set bit. There must be one. */
			while ((bit & map) == 0) {
				bin = next_bin(bin);
				bit <<= 1;
				assert(bit != 0);
			}

			/* Inspect the bin. It is likely to be non-empty */
			victim = last(bin);

			/*  If a false alarm (empty bin), clear the bit. */
			if (victim == bin) {
				av->binmap[block] = map &= ~bit; /* Write through */
				bin = next_bin(bin);
				bit <<= 1;
			}

			else {
				size = chunksize(victim);

				/*  We know the first chunk in this bin is big enough to use. */
				assert((unsigned long)(size) >= (unsigned long)(nb));

				remainder_size = size - nb;

				/* unlink */
				malloc_unlink(victim, bck, fwd);

				/* Exhaust */
				if (remainder_size < MINSIZE) {
					set_inuse_bit_at_offset(victim, size);
					if (av != &main_arena)
						victim->size |= NON_MAIN_ARENA;
				}

				/* Split */
				else {
					remainder = chunk_at_offset(victim, nb);
					mm.type = FROM_SPLIT;
					mm.remainder_ptr = remainder;
					/* We cannot assume the unsorted list is empty and therefore
					   have to perform a complete insert here.  */
					bck = unsorted_chunks(av);
					fwd = bck->fd;
					if (__builtin_expect(fwd->bk != bck, 0))
					{
						printf("malloc(): corrupted unsorted chunks 2");
						return mm;
					}
					remainder->bk = bck;
					remainder->fd = fwd;
					bck->fd = remainder;
					fwd->bk = remainder;

					/* advertise as last remainder */
					if (in_smallbin_range(nb))
						av->last_remainder = remainder;
					if (!in_smallbin_range(remainder_size))
					{
						remainder->fd_nextsize = NULL;
						remainder->bk_nextsize = NULL;
					}
					set_head(victim, nb | PREV_INUSE |
						(av != &main_arena ? NON_MAIN_ARENA : 0));
					set_head(remainder, remainder_size | PREV_INUSE);
					set_foot(remainder, remainder_size);
				}
				//check_malloced_chunk(av, victim, nb);
				void* p = chunk2mem(victim);
				mm.mm_ptr = p;
				return mm;
			}
		}

	use_top:
		victim = av->top;
		size = chunksize(victim);

		if ((unsigned long)(size) >= (unsigned long)(nb + MINSIZE)) {
			remainder_size = size - nb;
			remainder = chunk_at_offset(victim, nb);
			mm.remainder_ptr = remainder;
			mm.type = FROM_SPLIT;
			av->top = remainder;
			set_head(victim, nb | PREV_INUSE |
				(av != &main_arena ? NON_MAIN_ARENA : 0));
			set_head(remainder, remainder_size | PREV_INUSE);

			//check_malloced_chunk(av, victim, nb);
			void* p = chunk2mem(victim);
			mm.mm_ptr = p;
			return mm;
		}

		else if (have_fastchunks(av)) {
			assert(in_smallbin_range(nb));
			malloc_consolidate(av);
			idx = smallbin_index(nb); /* restore original bin index */
		}
		else {
			mm = sYSMALLOc(nb, av);
			return mm;
		}
	}
}


mm_info sYSMALLOc(INTERNAL_SIZE_T nb, mstate av)
{
	mchunkptr       old_top;        /* incoming value of av->top */
	INTERNAL_SIZE_T old_size;       /* its size */
	char* old_end;        /* its end address */

	long            size;           /* arg to first MORECORE or mmap call */
	char* brk;            /* return value from MORECORE */

	long            correction;     /* arg to 2nd MORECORE call */
	char* snd_brk;        /* 2nd return val */

	INTERNAL_SIZE_T front_misalign; /* unusable bytes at front of new space */
	INTERNAL_SIZE_T end_misalign;   /* partial page left at end of new space */
	char* aligned_brk;    /* aligned offset into brk */

	mchunkptr       p;              /* the allocated/returned chunk */
	mchunkptr       remainder;      /* remainder from allocation */
	unsigned long   remainder_size; /* its size */

	unsigned long   sum;            /* for updating stats */

	size_t          pagemask = mp_.pagesize - 1;
	bool            tried_mmap = false;
	mm_info         mmInfo;
	mmInfo.mm_ptr = NULL;
	/*
	  If have mmap, and the request size meets the mmap threshold, and
	  the system supports mmap, and there are few enough currently
	  allocated mmapped regions, try to directly map this request
	  rather than expanding top.
	*/

	if ((unsigned long)(nb) >= (unsigned long)(mp_.mmap_threshold) &&
		(mp_.n_mmaps < mp_.n_mmaps_max)) {

		char* mm;             /* return value from mmap call*/

	try_mmap:
		/*
		  Round up size to nearest page.  For mmapped chunks, the overhead
		  is one SIZE_SZ unit larger than for normal chunks, because there
		  is no following chunk whose prev_size field could be used.
		*/
		/* See the front_misalign handling below, for glibc there is no
		   need for further alignments.  */
		size = (nb + SIZE_SZ + pagemask) & ~pagemask;

		tried_mmap = true;

		/* Don't try if size wraps around 0 */
		if ((unsigned long)(size) > (unsigned long)(nb)) {

			mm = (char*)(MMAP(0, size, PROT_READ | PROT_WRITE, MAP_PRIVATE));

			if (mm != MAP_FAILED) {

				/*
				  The offset to the start of the mmapped region is stored
				  in the prev_size field of the chunk. This allows us to adjust
				  returned start address to meet alignment requirements here
				  and in memalign(), and still be able to compute proper
				  address argument for later munmap in free() and realloc().
				*/

				/* For glibc, chunk2mem increases the address by 2*SIZE_SZ and
				   MALLOC_ALIGN_MASK is 2*SIZE_SZ-1.  Each mmap'ed area is page
				   aligned and therefore definitely MALLOC_ALIGN_MASK-aligned.  */
				assert(((INTERNAL_SIZE_T)chunk2mem(mm) & MALLOC_ALIGN_MASK) == 0);

				{
					p = (mchunkptr)mm;
					set_head(p, size | IS_MMAPPED);
				}

				/* update statistics */

				if (++mp_.n_mmaps > mp_.max_n_mmaps)
					mp_.max_n_mmaps = mp_.n_mmaps;

				sum = mp_.mmapped_mem += size;
				if (sum > (unsigned long)(mp_.max_mmapped_mem))
					mp_.max_mmapped_mem = sum;
				//check_chunk(av, p);
				mmInfo.type = FROM_MMAP;
				mmInfo.mm_ptr = chunk2mem(p);
				return mmInfo;
			}
		}
	}


	/* Record incoming configuration of top */

	old_top = av->top;
	old_size = chunksize(old_top);
	old_end = (char*)(chunk_at_offset(old_top, old_size));

	brk = snd_brk = (char*)(MORECORE_FAILURE);
	if (av != &main_arena) {

		heap_info* old_heap, * heap;
		size_t old_heap_size;

		/* First try to extend the current heap. */
		old_heap = heap_for_ptr(old_top);
		old_heap_size = old_heap->size;
		if ((long)(MINSIZE + nb - old_size) > 0
			&& grow_heap(old_heap, MINSIZE + nb - old_size) == 0) {
			av->system_mem += old_heap->size - old_heap_size;
			arena_mem += old_heap->size - old_heap_size;
			set_head(old_top, (((char*)old_heap + old_heap->size) - (char*)old_top)
				| PREV_INUSE);
		}
		else if ((heap = new_heap(nb + (MINSIZE + sizeof(*heap)), mp_.top_pad))) {
			/* Use a newly allocated heap.  */
			heap->ar_ptr = av;
			heap->prev = old_heap;
			av->system_mem += heap->size;
			arena_mem += heap->size;
			/* Set up the new top.  */
			top(av) = chunk_at_offset(heap, sizeof(*heap));
			set_head(top(av), (heap->size - sizeof(*heap)) | PREV_INUSE);

			/* Setup fencepost and free the old top chunk. */
			/* The fencepost takes at least MINSIZE bytes, because it might
		   become the top chunk again later.  Note that a footer is set
		   up, too, although the chunk is marked in use. */
			old_size -= MINSIZE;
			set_head(chunk_at_offset(old_top, old_size + 2 * SIZE_SZ), 0 | PREV_INUSE);
			if (old_size >= MINSIZE) {
				set_head(chunk_at_offset(old_top, old_size), (2 * SIZE_SZ) | PREV_INUSE);
				set_foot(chunk_at_offset(old_top, old_size), (2 * SIZE_SZ));
				set_head(old_top, old_size | PREV_INUSE | NON_MAIN_ARENA);
				_int_free(av, old_top);
			}
			else {
				set_head(old_top, (old_size + 2 * SIZE_SZ) | PREV_INUSE);
				set_foot(old_top, (old_size + 2 * SIZE_SZ));
			}
		}
		else if (!tried_mmap)
			/* We can at least try to use to mmap memory.  */
			goto try_mmap;

	}
	else { /* av == main_arena */
		/* Request enough space for nb + pad + overhead */
		size = nb + mp_.top_pad + MINSIZE;
		if (contiguous(av))
			size -= old_size;
		size = (size + pagemask) & ~pagemask;
		if (size > 0)
			brk = (char*)(sbrk(size)); //expand the top of the heap;

		if(brk == (char*)(MORECORE_FAILURE)) {
			/* Cannot merge with old top, so add its size back in */
			if (contiguous(av))
				size = (size + old_size + pagemask) & ~pagemask;

			/* If we are relying on mmap as backup, then use larger units */
			if ((unsigned long)(size) < (unsigned long)(MMAP_AS_MORECORE_SIZE))
				size = MMAP_AS_MORECORE_SIZE;

			/* Don't try if size wraps around 0 */
			if ((unsigned long)(size) > (unsigned long)(nb)) {

				char* mbrk = (char*)(MMAP(0, size, PROT_READ | PROT_WRITE, MAP_PRIVATE));

				if (mbrk != MAP_FAILED) {

					/* We do not need, and cannot use, another sbrk call to find end */
					brk = mbrk;
					snd_brk = brk + size;


					set_noncontiguous(av);
				}
			}
		}

		if (brk != (char*)(MORECORE_FAILURE)) { //success
			if (mp_.sbrk_base == 0)
				mp_.sbrk_base = brk;
			av->system_mem += size;
			if (brk == old_end && snd_brk == (char*)(MORECORE_FAILURE))
				set_head(old_top, (size + old_size) | PREV_INUSE);

			else if (contiguous(av) && old_size && brk < old_end) {
				/* Someone else killed our space..  Can't touch anything.  */
				printf("break adjusted to free malloc space");
			}
			else {
				front_misalign = 0;
				end_misalign = 0;
				correction = 0;
				aligned_brk = brk;

				/* handle contiguous cases */
				if (contiguous(av)) {

					/* Count foreign sbrk as system_mem.  */
					if (old_size)
						av->system_mem += brk - old_end;

					/* Guarantee alignment of first new chunk made from this space */

					front_misalign = (INTERNAL_SIZE_T)chunk2mem(brk) & MALLOC_ALIGN_MASK;
					if (front_misalign > 0) {
						correction = MALLOC_ALIGNMENT - front_misalign;
						aligned_brk += correction;
					}
					correction += old_size;
					/* Extend the end address to hit a page boundary */
					end_misalign = (INTERNAL_SIZE_T)(brk + size + correction);
					correction += ((end_misalign + pagemask) & ~pagemask) - end_misalign;

					assert(correction >= 0);
					snd_brk = (char*)(sbrk(correction));
					if (snd_brk == (char*)(MORECORE_FAILURE)) {
						correction = 0;
						snd_brk = (char*)(sbrk(0));
					}
				}
				/* handle non-contiguous cases */
				else {
					/* MORECORE/mmap must correctly align */
					assert(((unsigned long)chunk2mem(brk) & MALLOC_ALIGN_MASK) == 0);
					/* Find out current end of memory */
					if (snd_brk == (char*)(MORECORE_FAILURE)) {
						snd_brk = (char*)(sbrk(0));
					}	
				}

				/* Adjust top based on results of second sbrk */
				if (snd_brk != (char*)(MORECORE_FAILURE)) {
					av->top = (mchunkptr)aligned_brk;
					set_head(av->top, (snd_brk - aligned_brk + correction) | PREV_INUSE);
					av->system_mem += correction;
					if (old_size != 0) {
						old_size = (old_size - 4 * SIZE_SZ) & ~MALLOC_ALIGN_MASK;
						set_head(old_top, old_size | PREV_INUSE);
						chunk_at_offset(old_top, old_size)->size =
							(2 * SIZE_SZ) | PREV_INUSE;

						chunk_at_offset(old_top, old_size + 2 * SIZE_SZ)->size =
							(2 * SIZE_SZ) | PREV_INUSE;

						/* If possible, release the rest. */
						if (old_size >= MINSIZE) {
							_int_free(av, old_top);
						}

					}
				}
			}
		}

	} /* if (av !=  &main_arena) */
 
	if ((unsigned long)av->system_mem > (unsigned long)(av->max_system_mem))
		av->max_system_mem = av->system_mem;
	check_malloc_state(av);

	/* finally, do the allocation */
	p = av->top;
	size = chunksize(p);

	/* check that one of the above allocation paths succeeded */
	if ((unsigned long)(size) >= (unsigned long)(nb + MINSIZE)) {
		remainder_size = size - nb;
		remainder = chunk_at_offset(p, nb);
		av->top = remainder;
		set_head(p, nb | PREV_INUSE | (av != &main_arena ? NON_MAIN_ARENA : 0));
		set_head(remainder, remainder_size | PREV_INUSE);
		//check_malloced_chunk(av, p, nb);
		mmInfo.mm_ptr = chunk2mem(p);
		mmInfo.type = FROM_SPLIT;
		mmInfo.remainder_ptr = remainder; //有问题
		return mmInfo;
	}

	/* catch all failure paths */
	errno = ENOMEM;
	return mmInfo;
}

static void _int_free(mstate av, mchunkptr p)
{
	INTERNAL_SIZE_T size;        /* its size */
	mfastbinptr* fb;          /* associated fastbin */
	mchunkptr       nextchunk;   /* next contiguous chunk */
	INTERNAL_SIZE_T nextsize;    /* its size */
	int             nextinuse;   /* true if nextchunk is used */
	INTERNAL_SIZE_T prevsize;    /* size of previous contiguous chunk */
	mchunkptr       bck;         /* misc temp for linking */
	mchunkptr       fwd;         /* misc temp for linking */

	const char* errstr = NULL;

	size = chunksize(p);
	/* We know that each chunk is at least MINSIZE bytes in size.  */
	if (__builtin_expect(size < MINSIZE, 0))
	{
		printf("free(): invalid size");
		return;
	}
	//check_inuse_chunk(av, p);
	if ((unsigned long)(size) <= (unsigned long)(get_max_fast())) {
		if (__builtin_expect(chunk_at_offset(p, size)->size <= 2 * SIZE_SZ, 0)
			|| __builtin_expect(chunksize(chunk_at_offset(p, size))
				>= av->system_mem, 0))
		{
			{
				printf("free(): invalid next size (fast)");
				return;
			}
		}
		set_fastchunks(av);
		unsigned int idx = fastbin_index(size);
		fb = &fastbin(av, idx);

		/* Another simple check: make sure the top of the bin is not the
		   record we are going to add (i.e., double free).  */
		if (__builtin_expect(*fb == p, 0))
		{
			printf("double free or corruption (fasttop)");
			return;
		}
		if (*fb != NULL
			&& __builtin_expect(fastbin_index(chunksize(*fb)) != idx, 0))
		{
			printf("invalid fastbin entry (free)");
			return;
		}

		p->fd = *fb;
		*fb = p;
	}

	/*
	  Consolidate other non-mmapped chunks as they arrive.
	*/

	else if (!chunk_is_mmapped(p)) {
		nextchunk = chunk_at_offset(p, size);

		/* Lightweight tests: check whether the block is already the
		   top block.  */
		if (__builtin_expect(p == av->top, 0))
		{
			printf("double free or corruption (top)");
			return;
		}
		/* Or whether the next chunk is beyond the boundaries of the arena.  */
		if (__builtin_expect(contiguous(av)
			&& (char*)nextchunk
			>= ((char*)av->top + chunksize(av->top)), 0))
		{
			errstr = "double free or corruption (out)";
			return;
		}
		/* Or whether the block is actually not marked used.  */
		if (__builtin_expect(!prev_inuse(nextchunk), 0))
		{
			errstr = "double free or corruption (!prev)";
			return;
		}

		nextsize = chunksize(nextchunk);
		if (__builtin_expect(nextchunk->size <= 2 * SIZE_SZ, 0)
			|| __builtin_expect(nextsize >= av->system_mem, 0))
		{
			errstr = "free(): invalid next size (normal)";
			return;
		}
		/* consolidate backward */
		if (!prev_inuse(p)) {
			prevsize = p->prev_size;
			size += prevsize;
			p = chunk_at_offset(p, -((long)prevsize));
			malloc_unlink(p, bck, fwd);
		}

		if (nextchunk != av->top) {
			/* get and clear inuse bit */
			nextinuse = inuse_bit_at_offset(nextchunk, nextsize);

			/* consolidate forward */
			if (!nextinuse) {
				malloc_unlink(nextchunk, bck, fwd);
				size += nextsize;
			}
			else
				clear_inuse_bit_at_offset(nextchunk, 0);

			/*
		  Place the chunk in unsorted chunk list. Chunks are
		  not placed into regular bins until after they have
		  been given one chance to be used in malloc.
			*/

			bck = unsorted_chunks(av);
			fwd = bck->fd;
			if (__builtin_expect(fwd->bk != bck, 0))
			{
				errstr = "free(): corrupted unsorted chunks";
				return;
			}
			p->fd = fwd;
			p->bk = bck;
			if (!in_smallbin_range(size))
			{
				p->fd_nextsize = NULL;
				p->bk_nextsize = NULL;
			}
			bck->fd = p;
			fwd->bk = p;

			set_head(p, size | PREV_INUSE);
			set_foot(p, size);

			//check_free_chunk(av, p);
		}

		/*
		  If the chunk borders the current high end of memory,
		  consolidate into top
		*/

		else {
			size += nextsize;
			set_head(p, size | PREV_INUSE);
			av->top = p;
			//check_chunk(av, p);
		}
		if ((unsigned long)(size) >= FASTBIN_CONSOLIDATION_THRESHOLD) {
			if (have_fastchunks(av))
				malloc_consolidate(av);

			if (av == &main_arena) {
				if ((unsigned long)(chunksize(av->top)) >=
					(unsigned long)(mp_.trim_threshold))
					sYSTRIm(mp_.top_pad, av);
			}
			else {
				/* Always try heap_trim(), even if the top chunk is not
				   large, because the corresponding heap might go away.  */
				heap_info* heap = heap_for_ptr(top(av));

				assert(heap->ar_ptr == av);
				heap_trim(heap, mp_.top_pad);
			}
		}
	}
	else {
		munmap_chunk(p);
	}
}
static void munmap_chunk(mchunkptr p)
{
	INTERNAL_SIZE_T size = chunksize(p);
	assert(chunk_is_mmapped(p));
	uintptr_t block = (uintptr_t)p - p->prev_size;
	size_t total_size = p->prev_size + size;
	if (__builtin_expect(((block | total_size) & (mp_.pagesize - 1)) != 0, 0))
	{
		printf("munmap_chunk(%): invalid pointer", chunk2mem(p));
		return;
	}
	mp_.n_mmaps--;
	mp_.mmapped_mem -= total_size;
	int ret __attribute__((unused)) = munmap((char*)block, total_size);
}
/* Grow a heap.  size is automatically rounded up to a
   multiple of the page size. */
static int grow_heap(heap_info* h, long diff)
{
	size_t page_mask = malloc_getpagesize - 1;
	long new_size;

	diff = (diff + page_mask) & ~page_mask;
	new_size = (long)h->size + diff;
	if ((unsigned long)new_size > (unsigned long)HEAP_MAX_SIZE)
		return -1;
	if ((unsigned long)new_size > h->mprotect_size) {
		if (mprotect((char*)h + h->mprotect_size,
			(unsigned long)new_size - h->mprotect_size,
			PROT_READ | PROT_WRITE) != 0)
			return -2;
		h->mprotect_size = new_size;
	}

	h->size = new_size;
	return 0;
}

static void ptmalloc_init()
{
	char* s;
	int secure = 0;
	if (__malloc_initialized > 0)
		return;
	__malloc_initialized = 0;
	ptmalloc_init_minimal();
	mutex_init(&main_arena.mutex);
	main_arena.next = &main_arena;
	mutex_init(&list_lock);
	tsd_key_create(&arena_key, NULL);
	tsd_setspecific(arena_key, (void*)& main_arena);
	pthread_atfork(ptmalloc_lock_all, ptmalloc_unlock_all, ptmalloc_unlock_all2); //防止fork子进程时死锁/
	__malloc_initialized = 1;
}

#define ATFORK_ARENA_PTR ((void*)-1)
static unsigned int atfork_recursive_cntr;

static void ptmalloc_lock_all() {
	mstate ar_ptr;
	if (__malloc_initialized < 1)
		return;
	if (mutex_trylock(&list_lock)) {
		void* my_arena;
		tsd_getspecific(arena_key, my_arena);
		if (my_arena == ATFORK_ARENA_PTR)
			return;
		mutex_lock(&list_lock);
	}
	for (ar_ptr = &main_arena;;) {
		mutex_lock(&ar_ptr->mutex);
		ar_ptr = ar_ptr->next;
		if (ar_ptr == &main_arena)
			goto out;
	}
	tsd_getspecific(arena_key, save_arena);       //保存一下
	tsd_setspecific(arena_key, ATFORK_ARENA_PTR); //只要有一个fork()的时候把所有锁都锁了 后面的就可以不用再等解锁后重新上锁了 类似操作系统里讲的单向过桥问题
out:++atfork_recursive_cntr;
}

static void ptmalloc_unlock_all() {
	mstate ar_ptr;
	if (__malloc_initialized < 1)
		return;
	if (--atfork_recursive_cntr != 0)
		return;
	tsd_setspecific(arena_key, save_arena);
	for (ar_ptr = &main_arena;;) {
		mutex_unlock(&ar_ptr->mutex);
		ar_ptr = ar_ptr -> next;
		if (ar_ptr == &main_arena)
			break;
	}
	mutex_unlock(&list_lock);
}

static void ptmalloc_unlock_all2() {
	mstate ar_ptr;
	if (__malloc_initialized < 1)
		return;
	free_list = NULL;
	tsd_setspecific(arena_key, save_arena);
	for (ar_ptr = &main_arena;;) {
		mutex_init(&ar_ptr->mutex);  //子进程继承的mutex是不安全的
		if (ar_ptr != save_arena) {
			ar_ptr->next_free = free_list;
			free_list = ar_ptr;
		}
		ar_ptr = ar_ptr->next;
		if (ar_ptr == &main_arena)
			break;
	}
	mutex_init(&list_lock);
	atfork_recursive_cntr = 0;
}

//参数初始化
static void ptmalloc_init_minimal() {
#if DEFAULT_TOP_PAD != 0  
	mp_.top_pad        = DEFAULT_TOP_PAD;
#endif   
	mp_.n_mmaps_max    = DEFAULT_MMAP_MAX;   
	mp_.mmap_threshold = DEFAULT_MMAP_THRESHOLD;   
	mp_.trim_threshold = DEFAULT_TRIM_THRESHOLD;   
	mp_.pagesize       = malloc_getpagesize;  
	mp_.arena_test = 8;
	nareans = 1; 
}


//初始化分配区
static void malloc_init_state(mstate av) {
	int i;
	mbinptr bin;
	for (i = 1; i < NBINS; ++i) {
		bin = bin_at(av,i);
		bin->fd = bin->bk = bin;
	}
	//av->treetop = NULL;
	av->top = initial_top(av);
	if (av == &main_arena){
		set_max_fast(DEFAULT_MAXFAST);
		pthread_mutex_init(&list_lock, NULL);
		//free_list = av;
		//free_list->next_free = av;
	}
	else
		set_noncontiguous(av);
	pthread_mutex_init(&av->mutex,NULL);
	av->next = NULL;
}


static char* aligned_heap_area; //上一次mmap的结束地址

/* Create a new heap.  size is automatically rounded up to a multiple
	of the page size. */
static heap_info_ptr new_heap(size_t size, size_t top_pad)
{ 
	size_t page_mask = malloc_getpagesize - 1;
	char* p1,* p2;
	unsigned long ul;
	heap_info_ptr h;
	if (size + top_pad < HEAP_MIN_SIZE)     
		size = HEAP_MIN_SIZE;   
	else if (size + top_pad <= HEAP_MAX_SIZE)     
		size += top_pad;   
	else if (size > HEAP_MAX_SIZE)     
		return 0;   
	else size = HEAP_MAX_SIZE;   
		size = (size + page_mask) & ~page_mask;

	 /* A memory region aligned to a multiple of HEAP_MAX_SIZE is needed.
		 No swap space needs to be reserved for the following large
		 mapping (on Linux, this is the case for all non - writable mappings
		 anyway). */
	p2 = MAP_FAILED;   
	if (aligned_heap_area) {
		p2 = (char*)MMAP(aligned_heap_area, HEAP_MAX_SIZE, PROT_NONE, MAP_PRIVATE | MAP_NORESERVE);
		aligned_heap_area = NULL;
		if (p2 != MAP_FAILED && ((unsigned long)p2 & (HEAP_MAX_SIZE - 1))) {
			munmap(p2, HEAP_MAX_SIZE);
			p2 = MAP_FAILED;
		}
	}
	if (p2 == MAP_FAILED) {
		p1 = (char*)MMAP(0, HEAP_MAX_SIZE << 1, PROT_NONE, MAP_PRIVATE | MAP_NORESERVE);
		if (p1 != MAP_FAILED) {
			p2 = (char*)(((unsigned long)p1 + (HEAP_MAX_SIZE - 1)) & ~(HEAP_MAX_SIZE - 1));
			ul = p2 - p1;
			if (ul)
				munmap(p1, ul);
			else
				aligned_heap_area = p2 + HEAP_MAX_SIZE;
			munmap(p2 + HEAP_MAX_SIZE, HEAP_MAX_SIZE - ul);
		} 
		else {       /* Try to take the chance that an allocation of only HEAP_ MAX_SIZE is already aligned. */
			p2 = (char *)MMAP(0, HEAP_MAX_SIZE, PROT_NONE, MAP_PRIVATE|MAP_NORESERVE);       
			if(p2 == MAP_FAILED)         
				return 0;       
			if((unsigned long)p2 & (HEAP_MAX_SIZE-1)) {        
				munmap(p2, HEAP_MAX_SIZE);         
				return 0;       
			}
		}
	}   
	if (mprotect(p2, size, PROT_READ | PROT_WRITE) != 0) {
			munmap(p2, HEAP_MAX_SIZE);
			return 0; 
	}   
	h = (heap_info*)p2;
	h->size = size;
	h->mprotect_size = size;
	return h;
}

void* malloc(int bytes) {
	mm_info mm;
	mchunkptr p;
	mstate ar_ptr;
	mm = _malloc(bytes);
	if (mm.mm_ptr = NULL)
		return NULL;
	p = mem2chunk(mm.mm_ptr);
	if (chunk_is_mmapped(p)) // if chunk from mmap, return
	{
		return mm.mm_ptr;
	}
	ar_ptr = arena_for_chunk(p);
	(void)mutex_lock(&ar_ptr->mutex);
	if (ar_ptr->treetop.lf == NULL && ar_ptr->treetop.rt == NULL) {//without inialization
		if (mm.type = FROM_SPLIT) {
			ar_ptr->treetop.lf = 
		}
		treeNode node;
		node.wait_free = false;
	}
	(void)mutex_unlock(&ar_ptr->mutex);
}
void* simple_malloc(int bytes) {
	return _malloc(bytes).mm_ptr;
}
mm_info _malloc(int bytes) {
	mstate ar_ptr;
	mm_info mm;
	mm.mm_ptr = NULL;
	void* victim;
	if (__malloc_initialized <= 0)
		ptmalloc_init();
	if (__builtin_expect(bytes < 0,0))
		return mm;
	ar_ptr=arena_lookup();
	arena_lock(ar_ptr, bytes);
	if (!ar_ptr)
		return mm;
	mm = _int_malloc(ar_ptr, bytes);
	victim = mm.mm_ptr;
	if (!victim) {
		/* Maybe the failure is due to running out of mmapped areas. */
		if (ar_ptr != &main_arena) {
			(void)mutex_unlock(&ar_ptr->mutex);
			ar_ptr = &main_arena;
			(void)mutex_lock(&ar_ptr->mutex);
			mm = _int_malloc(ar_ptr, bytes);
			victim = mm.mm_ptr;
			(void)mutex_unlock(&ar_ptr->mutex);
		}
		else {
			/* ... or sbrk() has failed and there is still a chance to mmap() */
			ar_ptr = arean_get2((ar_ptr->next ? ar_ptr : 0, bytes));
			(void)mutex_unlock(&main_arena.mutex);
			if (ar_ptr) {
				mm = _int_malloc(ar_ptr, bytes);
				victim = mm.mm_ptr;
				(void)mutex_unlock(&ar_ptr->mutex);
			}
		}
	}
	else
		(void)mutex_unlock(&ar_ptr->mutex);
	return mm;
}

static int sYSTRIm(size_t pad, mstate av)
{
	long  top_size;        /* Amount of top-most memory */
	long  extra;           /* Amount to release */
	long  released;        /* Amount actually released */
	char* current_brk;     /* address returned by pre-check sbrk call */
	char* new_brk;         /* address returned by post-check sbrk call */
	size_t pagesz;

	pagesz = mp_.pagesize;
	top_size = chunksize(av->top);
	extra = ((top_size - pad - MINSIZE + (pagesz - 1)) / pagesz - 1) * pagesz;

	if (extra > 0) {
		current_brk = (char*)(sbrk(0));
		if (current_brk == (char*)(av->top) + top_size) {
			sbrk(-extra);
			/* Call the `morecore' hook if necessary.  */
			new_brk = (char*)(sbrk(0));

			if (new_brk != (char*)MORECORE_FAILURE) {
				released = (long)(current_brk - new_brk);

				if (released != 0) {
					/* Success. Adjust top. */
					av->system_mem -= released;
					set_head(av->top, (top_size - released) | PREV_INUSE);
					check_malloc_state(av);
					return 1;
				}
			}
		}
	}
	return 0;
}

static int heap_trim(heap_info* heap, size_t pad)
{
	mstate ar_ptr = heap->ar_ptr;
	unsigned long pagesz = mp_.pagesize;
	mchunkptr top_chunk = top(ar_ptr), p, bck, fwd;
	heap_info* prev_heap;
	long new_size, top_size, extra;

	/* Can this heap go away completely? */
	while (top_chunk == chunk_at_offset(heap, sizeof(*heap))) {
		prev_heap = heap->prev;
		p = chunk_at_offset(prev_heap, prev_heap->size - (MINSIZE - 2 * SIZE_SZ));
		assert(p->size == (0 | PREV_INUSE)); /* must be fencepost */
		p = prev_chunk(p);
		new_size = chunksize(p) + (MINSIZE - 2 * SIZE_SZ);
		assert(new_size > 0 && new_size < (long)(2 * MINSIZE));
		if (!prev_inuse(p))
			new_size += p->prev_size;
		assert(new_size > 0 && new_size < HEAP_MAX_SIZE);
		if (new_size + (HEAP_MAX_SIZE - prev_heap->size) < pad + MINSIZE + pagesz)
			break;
		ar_ptr->system_mem -= heap->size;
		arena_mem -= heap->size;
		delete_heap(heap);
		heap = prev_heap;
		if (!prev_inuse(p)) { /* consolidate backward */
			p = prev_chunk(p);
			malloc_unlink(p, bck, fwd);
		}
		assert(((unsigned long)((char*)p + new_size) & (pagesz - 1)) == 0);
		assert(((char*)p + new_size) == ((char*)heap + heap->size));
		top(ar_ptr) = top_chunk = p;
		set_head(top_chunk, new_size | PREV_INUSE);
		/*check_chunk(ar_ptr, top_chunk);*/
	}
	top_size = chunksize(top_chunk);
	extra = ((top_size - pad - MINSIZE + (pagesz - 1)) / pagesz - 1) * pagesz;
	if (extra < (long)pagesz)
		return 0;
	/* Try to shrink. */
	if (shrink_heap(heap, extra) != 0)
		return 0;
	ar_ptr->system_mem -= extra;
	arena_mem -= extra;

	/* Success. Adjust top accordingly. */
	set_head(top_chunk, (top_size - extra) | PREV_INUSE);
	/*check_chunk(ar_ptr, top_chunk);*/
	return 1;
}

static int shrink_heap(heap_info* h, long diff)
{
	long new_size;

	new_size = (long)h->size - diff;
	if (new_size < (long)sizeof(*h))
		return -1;
	/* Try to re-map the extra heap space freshly to save memory, and
	   make it inaccessible. */
	if ((char*)MMAP((char*)h + new_size, diff, PROT_NONE,
		MAP_PRIVATE | MAP_FIXED) == (char*)MAP_FAILED)
		return -2;
	h->mprotect_size = new_size;
	h->size = new_size;
	return 0;
}

void public_fREe(void* mem)
{
	mstate ar_ptr;
	mchunkptr p;                          /* chunk corresponding to mem */
	if (mem == 0)                              /* free(0) has no effect */
		return;
	p = mem2chunk(mem);

	if (chunk_is_mmapped(p))                       /* release mmapped memory. */
	{
		/* see if the dynamic brk/mmap threshold needs adjusting */
		if (!mp_.no_dyn_threshold
			&& p->size > mp_.mmap_threshold
			&& p->size <= DEFAULT_MMAP_THRESHOLD_MAX)
		{
			mp_.mmap_threshold = chunksize(p);
			mp_.trim_threshold = 2 * mp_.mmap_threshold;
		}
		munmap_chunk(p);
		return;
	}
	ar_ptr = arena_for_chunk(p);
	(void)mutex_lock(&ar_ptr->mutex);
	_int_free(ar_ptr, p);
	(void)mutex_unlock(&ar_ptr->mutex);
}

void free(void* mem)
{
	mstate ar_ptr;
	mchunkptr p;                          /* chunk corresponding to mem */
	if (mem == 0)                              /* free(0) has no effect */
		return;
	p = mem2chunk(mem);
	if (chunk_is_mmapped(p))                       /* release mmapped memory. */
	{
		/* see if the dynamic brk/mmap threshold needs adjusting */
		if (!mp_.no_dyn_threshold
			&& p->size > mp_.mmap_threshold
			&& p->size <= DEFAULT_MMAP_THRESHOLD_MAX)
		{
			mp_.mmap_threshold = chunksize(p);
			mp_.trim_threshold = 2 * mp_.mmap_threshold;
		}
		munmap_chunk(p);
		return;
	}
	ar_ptr = arena_for_chunk(p);
	(void)mutex_lock(&ar_ptr->mutex);
	_int_free(ar_ptr, p);
	(void)mutex_unlock(&ar_ptr->mutex);
}