#include <errno.h>
#include "malloc.h"
#include <stdio.h>
#include <pthread.h>
#pragma comment(lib,"pthreadVC2.lib") 

void test1() {
	void* p, * q;
	//p = malloc(-1);
	if (p != NULL)
		printf("malloc (-1) succeeded.");
	q = malloc(10);
	if (q == NULL)
		printf("malloc (10) failed.");
	p = malloc(128);
	if (p == NULL)
		printf("malloc (10) failed.");
	//_free(q);
	_free(p);
	free(q);
	//free(p);
	p = malloc(0);
	if (p == NULL)
		printf("malloc (0) failed.");
	p = malloc(513 * 1024);
	if (p == NULL)
		printf("malloc (513K) failed.");
	q = malloc(-512 * 1024);
	if (q != NULL)
		printf("malloc (-512K) succeeded.");
	free(p);
	free(q);
}
void *test2(void*) {
	void* ptrarr[20];
	void* p,*q;

	for (int i = 1; i < 6; i++) {
		ptrarr[i] = malloc(50);
	}
	for (int i = 1; i < 5; i++) {
		free(ptrarr[i]);
	}
	p = malloc(256*1024);
	free(p);
	p=malloc(100);
	q=malloc(50);
	free(p);
	free(q);
}

void* test22(void*) {
	while(1){
		sleep(1);
		printf("test");
	}
}

void test3() {
	pthread_t thread[10];
	for (int i = 0; i < 4; i++) {
		if (pthread_create(&thread[i], NULL, test2, NULL) == -1) {
			puts("fail to create pthread t0");
		}
	}
	for (int i = 0; i < 4; i++) {
		if (pthread_join(thread[i], NULL) == -1) {
			puts("fail to recollect t1");
		}
	}
}

void *pthread_B(void*mem)
{
	//void* p, *q;
	//p = malloc(100);
	//q = malloc(50);
	_free(mem);
	//_free(q);
}

int main(void)
{
	void *p, *q,*m,*n;
	pthread_t B;
	p = malloc(200);
	q = malloc(50);
	pthread_create(&B, NULL, pthread_B, q);
	m = malloc(50);
	pthread_create(&B, NULL, pthread_B, m);
	n = malloc(50);
	pthread_create(&B, NULL, pthread_B, n);
	q = malloc(60);
	pthread_create(&B, NULL, pthread_B, q);

	free(p);
	pthread_join(B, 0);
}