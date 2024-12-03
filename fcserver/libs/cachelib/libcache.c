#include "libcache.h"
#include "libdiag.h"
#include "liblist.h"
#include "libspinlock.h"

struct cache_st
{
    struct list_head entry;
    struct list_head free_list;
    char name[32];
    uint16_t flags;
    uint32_t node_size;
    uint32_t node_cnt;
    uint32_t free_cnt;
    void* (*malloc)(size_t size);
    void (*free)(void* ptr);
    uint8_t* buffer;
    spinlock_t spinlock;
};

static int g_cache_inited = 0;
static spinlock_t g_cache_spinlock;
static struct list_head g_cache_list;

int cache_init(void)
{
    spinlock_init(&g_cache_spinlock);
    INIT_LIST_HEAD(&g_cache_list);
    g_cache_inited = 1;
    return 0;
}

cache_t* cache_find(char* name)
{
    struct cache_st* pcache;

    if ((name == NULL) || (name[0] == '\0'))
        return NULL;

    spinlock_lock(&g_cache_spinlock);
    list_for_each_entry(pcache, &g_cache_list, entry)
    {
        if (!strcmp(pcache->name, name))
        {
            spinlock_unlock(&g_cache_spinlock);
            return pcache;
        }
    }
    spinlock_unlock(&g_cache_spinlock);

    return NULL;
}

cache_t* cache_create(char* name, uint32_t flags, int item, int count,
                      void* (*malloc_func)(size_t size),
                      void (*free_func)(void* ptr))
{
    int i;
    void* addr;
    struct list_head* list;
    struct cache_st* pcache;

    if (unlikely(g_cache_inited == 0))
    {
        cache_init();
    }

    if (name == NULL || name[0] == '\0' || malloc_func == NULL ||
        free_func == NULL)
    {
        return NULL;
    }

    // item must greater then 2 pointer size!
    if (item <= sizeof(struct list_head) || count == 0)
    {
        return NULL;
    }

    pcache = cache_find(name);
    if (pcache)
    {
        return NULL;
    }

    pcache = malloc(sizeof(struct cache_st));
    if (pcache == NULL)
        return NULL;

    strncpy(pcache->name, name, sizeof(pcache->name));

    pcache->flags = flags;
    pcache->node_size = item;
    pcache->node_cnt = count;
    pcache->free_cnt = 0;
    pcache->malloc = malloc_func;
    pcache->free = free_func;

    pcache->buffer = pcache->malloc(item * count);
    if (pcache->buffer == NULL)
    {
        return NULL;
    }

    spinlock_init(&pcache->spinlock);
    INIT_LIST_HEAD(&pcache->free_list);
    for (i = 0; i < count; i++)
    {
        addr = pcache->buffer + i * item;
        list = (struct list_head*)addr;
        list_add_tail(list, &pcache->free_list);
        pcache->free_cnt++;
    }

    spinlock_lock(&g_cache_spinlock);
    list_add_tail(&pcache->entry, &g_cache_list);
    spinlock_unlock(&g_cache_spinlock);

    return pcache;
}

void cache_destroy(cache_t** pcache)
{
    struct cache_st* cache;

    if (pcache == NULL)
    {
        return;
    }

    cache = (struct cache_st*)*pcache;
    if (cache_find(cache->name) == NULL)
        return;

    if (cache->free_cnt != cache->node_cnt)
    {
        DIAG_ERROR(
            "some nodes of cache '%s' are in using! FREES:%u, TOTAL:%u\n",
            cache->name, cache->free_cnt, cache->node_cnt);
    }

    cache->free(cache->buffer);

    spinlock_lock(&g_cache_spinlock);
    list_del(&cache->entry);
    spinlock_unlock(&g_cache_spinlock);
    free(cache);

    *pcache = NULL;
    return;
}

void* cache_alloc(cache_t* cache)
{
    struct list_head* list;
    struct cache_st* pcache = cache;

    if (cache == NULL)
    {
        return NULL;
    }

    spinlock_lock(&pcache->spinlock);
    if (pcache->free_cnt == 0)
    {
        spinlock_unlock(&pcache->spinlock);
        return NULL;
    }

    list = pcache->free_list.next;
    list_del(list);
    pcache->free_cnt--;

    if (pcache->flags & CACHE_FLAG_ZERO)
    {
        memset((void*)list, 0, pcache->node_size);
    }

    spinlock_unlock(&pcache->spinlock);
    return (void*)list;
}

void cache_free(cache_t* cache, void* node)
{
    struct list_head* list;
    struct cache_st* pcache = cache;

    if (cache == NULL)
    {
        return;
    }

    spinlock_lock(&pcache->spinlock);
    list = (struct list_head*)node;
    list_add_tail(list, &pcache->free_list);
    pcache->free_cnt++;
    spinlock_unlock(&pcache->spinlock);

    return;
}

void cache_dump(void)
{
    struct cache_st* pcache;

    spinlock_lock(&g_cache_spinlock);
    list_for_each_entry(pcache, &g_cache_list, entry)
    {
        if (pcache->node_cnt != pcache->free_cnt)
        {
            DIAG_DEBUG(
                "cache %s node size %d count %d free %d buffer %p used %d\n",
                pcache->name, pcache->node_size, pcache->node_cnt,
                pcache->free_cnt, pcache->buffer,
                pcache->node_cnt - pcache->free_cnt);
        }
    }
    spinlock_unlock(&g_cache_spinlock);

    return;
}

void cache_fini(void)
{
    struct cache_st* pcache;
    struct cache_st* pcache_next;

    spinlock_lock(&g_cache_spinlock);
    list_for_each_entry_safe(pcache, pcache_next, &g_cache_list, entry)
    {
        if (pcache->free_cnt != pcache->node_cnt)
        {
            DIAG_ERROR(
                "some nodes of cache '%s' are not freed! FREES:%u, TOTAL:%u\n",
                pcache->name, pcache->free_cnt, pcache->node_cnt);
        }

        pcache->free(pcache->buffer);

        list_del(&pcache->entry);
        free(pcache);
    }
    spinlock_unlock(&g_cache_spinlock);

    spinlock_destroy(&g_cache_spinlock);
    g_cache_inited = 0;
    return;
}
