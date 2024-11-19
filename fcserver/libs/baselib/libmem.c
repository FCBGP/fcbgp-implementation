#include "libmem.h"
#include "librwlock.h"

#ifdef PRJ_SUPPORT_DEBUG

#define MEM_HTABLE_SIZE 8191

typedef struct mem_node_st {
    int size;
    void *ptr;
    int line;
    char file[512];
    struct mem_node_st *next;
} mem_node_t;

typedef struct mem_hlist_st {
    rwlock_t rwlock;
    mem_node_t *head;
} mem_hlist_t;

typedef struct mem_htable_st {
    long long used;
    mem_hlist_t buckets[MEM_HTABLE_SIZE];
} mem_htable_t;

static mem_htable_t g_mem_htable;

static uint32_t mem_hash(void *ptr)
{
    int i;
    uint32_t hval = 0x811c9dc5;
    long int intptr = (long int) ptr;
    uint8_t *buf = (uint8_t *) &intptr;

    /* FNV-1 hash each octet in the buffer */
    for (i = 0; i < sizeof(long int); i++) {
        /* multiply by the 32 bit FNV magic prime mod 2^32 */
        hval += (hval << 1) + (hval << 4) + (hval << 7) + (hval << 8) + (hval << 24);

        /* xor the bottom with the current octet */
        hval ^= (uint32_t) buf[i];
    }

    return hval % MEM_HTABLE_SIZE;
}

static int mem_hash_insert(void *ptr, int size, char *file, int line)
{
    mem_hlist_t *hlist;
    mem_node_t *cur_node, *new_node, *tmp_node, *prev_node;
    uint32_t hashval = mem_hash(ptr);

    hlist = g_mem_htable.buckets + hashval;

    new_node = malloc(sizeof(mem_node_t));
    if (new_node == NULL)
        return -ENOMEM;

    new_node->next = NULL;
    new_node->size = size;
    new_node->ptr = ptr;
    new_node->line = line;
    strncpy(new_node->file, file, sizeof(new_node->file));
    g_mem_htable.used += size;

    rwlock_wrlock(&hlist->rwlock);
    if (hlist->head) {
        cur_node = hlist->head;
        prev_node = hlist->head;
        /*
         * we sort the address from high to low, in order to delete faster.
         */
        while (cur_node && cur_node->ptr > ptr) {
            prev_node = cur_node;
            cur_node = cur_node->next;
        }

        if (cur_node) {
            if (cur_node == hlist->head) {
                tmp_node = hlist->head;
                hlist->head = new_node;
                new_node->next = tmp_node;
            } else {
                tmp_node = prev_node->next;
                prev_node->next = new_node;
                new_node->next = tmp_node;
            }
        } else {
            prev_node->next = new_node;
        }
    } else {
        hlist->head = new_node;
    }
    rwlock_wrunlock(&hlist->rwlock);

    return 0;
}

static int mem_hash_delete(void *ptr)
{
    int size;
    mem_hlist_t *hlist;
    mem_node_t *cur_node, *prev_node;
    uint32_t hashval = mem_hash(ptr);

    hlist = g_mem_htable.buckets + hashval;

    rwlock_wrlock(&hlist->rwlock);
    cur_node = hlist->head;
    prev_node = hlist->head;
    while (cur_node) {
        if (cur_node->ptr == ptr) {
            if (cur_node == hlist->head) {
                hlist->head = cur_node->next;
            } else {
                prev_node->next = cur_node->next;
            }
            g_mem_htable.used -= cur_node->size;
            size = cur_node->size;
            free(cur_node);
            rwlock_wrunlock(&hlist->rwlock);
            return size;
        }
        prev_node = cur_node;
        cur_node = cur_node->next;
    }
    rwlock_wrunlock(&hlist->rwlock);

    return -EINVAL;
}

static int mem_hash_init(void)
{
    int i;
    mem_hlist_t *hlist;

    g_mem_htable.used = 0;
    for (i = 0; i < MEM_HTABLE_SIZE; i++) {
        hlist = g_mem_htable.buckets + i;
        hlist->head = NULL;
        rwlock_init(&hlist->rwlock);
    }

    return 0;
}

static void mem_hash_fini(void)
{
    int i;
    mem_hlist_t *hlist;
    mem_node_t *cur_node, *tmp_node;

    if(g_mem_htable.used) {
        printf("Warning! %lld bytes memory leaked!\n", g_mem_htable.used);
        for (i = 0; i < MEM_HTABLE_SIZE; i++) {
            hlist = g_mem_htable.buckets + i;

            rwlock_wrlock(&hlist->rwlock);
            cur_node = hlist->head;
            while (cur_node) {
                tmp_node = cur_node->next;
                printf("  <0x%p/%04d> line [%04d] @ file [%s]\n", cur_node->ptr, cur_node->size, cur_node->line, cur_node->file);
                free(cur_node);
                cur_node = tmp_node;
            }
            rwlock_wrunlock(&hlist->rwlock);
        }
    }
}

void *memalloc_ex(int size, char *file, int line)
{
    int ret;
    void *ptr;

    ptr = malloc(size);
    if (ptr == NULL)
        return NULL;

    ret = mem_hash_insert(ptr, size, file, line);
    if (ret < 0) {
        free(ptr);
        return NULL;
    }

    return ptr;
}

void memfree(void *ptr)
{
    int size;

    if (ptr) {
        size = mem_hash_delete(ptr);
        if (size < 0) {
            printf("no such ptr %p!\n", ptr);
            return;
        }

        free(ptr);
    }
}

void *memrealloc_ex(char *ptr, int size, char *file, int line)
{
    int ret;
    void *nptr;

    if (ptr == NULL) {
        return memalloc_ex(size, file, line);
    }

    if (size == 0) {
        memfree(ptr);
        return NULL;
    }

    nptr = realloc(ptr, size);
    if (nptr == NULL) {
        return NULL;
    }

    ret = mem_hash_delete(ptr);
    if (ret < 0) {
        printf("no such old ptr %p!\n", ptr);
    }

    ret = mem_hash_insert(nptr, size, file, line);
    if (ret < 0) {
        free(nptr);
        return NULL;
    }

    return nptr;
}

int meminit(void)
{
    mem_hash_init();
    return 0;
}

void memfini(void)
{
    mem_hash_fini();
}

#endif
