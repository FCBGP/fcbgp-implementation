#ifndef __LIBMEM_H__
#define __LIBMEM_H__

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef PRJ_SUPPORT_DEBUG

extern int meminit(void);
extern void memfini(void);
extern void* memalloc_ex(int size, char* file, int line);
extern void* memrealloc_ex(char* ptr, int size, char* file, int line);
extern void memfree(void* ptr);

#define memalloc(size) memalloc_ex(size, __FILE__, __LINE__)
#define memrealloc(ptr, size) memrealloc_ex(ptr, size, __FILE__, __LINE__)

#else

#define meminit()
#define memfini()
#define memalloc(size) malloc(size)
#define memrealloc(ptr, size) realloc(ptr, size)
#define memfree(ptr) free(ptr)

#endif

#endif
