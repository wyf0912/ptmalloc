#include<stdio.h>
#include<unistd.h>
#include <stddef.h>
#include "malloc.h"

int main() {
	void* ptr;
	ptr=malloc(100);
	printf("test%d",sizeof(size_t));

}