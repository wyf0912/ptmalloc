#include "malloc.h"
#include <cerrno>
#include <unistd.h>

static mstate arean_get() {
	return NULL;
}

static mstate arean_get2(mstate a_tst, size_t size) {
	mstate a;

	return NULL;
}

void* malloc(size_t n) {
	if(global_max_fast==0){
		malloc_init_state(&main_arena);
	}
	mstate arean;
	if (arean == arean_get() == NULL)
		arean = arean_get2();
}

#define DEFAULT_MAXFAST 10
#define set_max_fast(s) (global_max_fast = (((s) == 0)   ? SMALLBIN_WIDTH: ((s + SIZE_SZ) & ~MALLOC_ALIGN_MASK)))
#define get_max_fast() (global_max_fast)

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