#pragma once
#ifndef ALIGN_H
#define ALIGN_H


#define INTERNAL_SIZE_T size_t
#define SIZE_SZ 8
#define MALLOC_ALIGNMENT 16
#define MALLOC_ALIGN_MASK (MALLOC_ALIGNMENT-1)
#define MINSIZE (sizeof(struct malloc_chunk))


#define chunk2mem(p)   ((void*)((char*)(p) + 2*SIZE_SZ))
#define mem2chunk(mem) ((mchunkptr)((char*)(mem) - 2*SIZE_SZ))

//将请求字节填充为可用大小，溢出时返回非零
#define request2size(req) (((req)+SIZE_SZ + MALLOC_ALIGN_MASK < MINSIZE) ?  MINSIZE : ((req)+SIZE_SZ + MALLOC_ALIGN_MASK) & ~MALLOC_ALIGN_MASK)


#endif // !ALIGN_H



