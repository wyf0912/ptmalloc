#include "malloc.h"
#include <cerrno>
#include <unistd.h>
#include "bins.h"
#include <pthread.h>
#include "bins.cpp"
 
#define FASTCHUNKS_BIT        (1U)
#define clear_fastchunks(M)    ((M)->flags |=  FASTCHUNKS_BIT)
#define set_fastchunks(M)      ((M)->flags &= ~FASTCHUNKS_BIT)

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
		/* Maybe size is too large to fit in a single heap.  So, just try
	  to create a minimally - sized arena and let malloc() attempt
	  to deal with the large request via mmap_chunk().  */
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
	if ((a = get_free_list()) == NULL && (a = reused_arena()) == NULL)
		a = new_arena(size);
	return a;
}


/*
  ------------------------- malloc_consolidate -------------------------

  malloc_consolidate is a specialized version of free() that tears
  down chunks held in fastbins.  Free itself cannot be used for this
  purpose since, among other things, it might place chunks back onto
  fastbins.  So, instead, we need to use a minor variant of the same
  code.

  Also, because this routine needs to be called the first time through
  malloc anyway, it turns out to be the perfect place to trigger
  initialization code.
*/


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

	/*
	  If max_fast is 0, we know that av hasn't
	  yet been initialized, in which case do so below
	*/

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
		check_malloc_state(av);
	}
}

static void* _int_malloc(mstate av, size_t bytes) {
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
	nb = request2size(bytes);
	if ((unsigned long)(nb) <= (unsigned long)(get_max_fast())) {
		idx = fastbin_index(nb);
		mfastbinptr* fb = &fastbin(av, idx);
		victim = *fb;
	}
	if (in_smallbin_range(nb)) {
		idx = smallbin_index(nb);     
		bin = bin_at(av, idx);
		if ((victim = last(bin)) != bin) {
			if (victim == 0) /* initialization check */
				malloc_consolidate(av);       
			else {
				bck = victim->bk;         
				if (__builtin_expect(bck->fd != victim, 0)) 
					printf("malloc(): smallbin double linked list corrupted");             
				goto errout; }         
				set_inuse_bit_at_offset(victim, nb);         
				bin->bk = bck;         
				bck->fd = bin;
				if (av != &main_arena)           
					victim->size |= NON_MAIN_ARENA;
					check_malloced_chunk(av, victim, nb);         
					void* p = chunk2mem(victim);         
					if (__builtin_expect(perturb_byte, 0))           
						alloc_perturb(p, bytes);         
					return p;
			}
		}
	}//还没写完
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
#endif   mp_.n_mmaps_max    = DEFAULT_MMAP_MAX;   
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


void* malloc(size_t bytes) {
	mstate ar_ptr;
	void* victim;
	if (__malloc_initialized <= 0)
		ptmalloc_init();
	ar_ptr=arena_lookup();
	arena_lock(ar_ptr, bytes);
	if (!ar_ptr)
		return 0;
	victim = _int_malloc(ar_ptr, bytes);
	if (!victim) {
		/* Maybe the failure is due to running out of mmapped areas. */
		if (ar_ptr != &main_arena) {
			(void)mutex_unlock(&ar_ptr->mutex);
			ar_ptr = &main_arena;
			(void)mutex_lock(&ar_ptr->mutex);
			victim = _int_malloc(ar_ptr, bytes);
			(void)mutex_unlock(&ar_ptr->mutex);
		}
		else {
			/* ... or sbrk() has failed and there is still a chance to mmap() */
			ar_ptr = arean_get2((ar_ptr->next ? ar_ptr : 0, bytes));
			(void)mutex_unlock(&main_arena.mutex);
			if (ar_ptr) {
				victim = _int_malloc(ar_ptr, bytes);
				(void)mutex_unlock(&ar_ptr->mutex);
			}
		}
	}
	else
		(void)mutex_unlock(&ar_ptr->mutex);
	//assert(!victim || chunk_is_mmapped(mem2chunk(victim)) ||
	//	ar_ptr == arena_for_chunk(mem2chunk(victim)));
	return victim;
}