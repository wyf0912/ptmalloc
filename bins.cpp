/* Take a chunk off a bin list */
#include "bins.h"
#include<assert.h>

/* The otherwise unindexable 1-bin is used to hold unsorted chunks. */

mbinptr bin_at(mstate m, int i) {
	return (mbinptr)(((char*) & ((m)->bins[((i)-1) * 2])) - offsetof(struct malloc_chunk, fd));
}
/* Take a chunk off a bin list */
void malloc_unlink(mchunkptr P, mchunkptr BK, mchunkptr FD) { 
	FD = P->fd; 
	BK = P->bk; 
	if (__builtin_expect(FD->bk != P || BK->fd != P, 0))
		//	 (check_action, "corrupted double-linked list", P);
		printf("corrupted double-linked list");
	else { 
		FD->bk = BK; 
		BK->fd = FD; 
		if (!in_smallbin_range(P->size) && __builtin_expect(P->fd_nextsize != NULL, 0)) {
			assert(P->fd_nextsize->bk_nextsize == P);
			assert(P->bk_nextsize->fd_nextsize == P);
			if (FD->fd_nextsize == NULL) {
				if (P->fd_nextsize == P)
					FD->fd_nextsize = FD->bk_nextsize = FD;
				else {
					FD->fd_nextsize = P->fd_nextsize;
					FD->bk_nextsize = P->bk_nextsize;
					P->fd_nextsize->bk_nextsize = FD;
					P->bk_nextsize->fd_nextsize = FD;
				}
			}
			else {
				P->fd_nextsize->bk_nextsize = P->bk_nextsize;
				P->bk_nextsize->fd_nextsize = P->fd_nextsize;
			}
		}
	}
}
