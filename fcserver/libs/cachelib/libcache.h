#ifndef LIBCACHE_H
#define LIBCACHE_H 1

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#define CACHE_FLAG_ZERO     0x01

typedef void cache_t;

extern cache_t *cache_find(char *name);
extern cache_t *cache_create(char *name, uint32_t flags, int item, int count,
        void *(*malloc_func)(size_t size), void (*free_func)(void *ptr));
extern void cache_destroy(cache_t **pcache);
extern void *cache_alloc(cache_t *cache);
extern void cache_free(cache_t *cache, void *node);
extern void cache_dump(void);
extern int cache_init(void);
extern void cache_fini(void);

#endif
