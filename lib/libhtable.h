#ifndef __LIBXTBL_H__
#define __LIBXTBL_H__

#include <errno.h>

#include "liblist.h"
#include "librwlock.h"
#include "libatomic.h"

typedef struct htbl_hlist_st {
    int changes;
    int nodecnt;
    rwlock_t rwlock;
    struct hlist_head head;
} htbl_hlist_t;

typedef struct htbl_node_st {
    int idx;
    int hval;
    atomic_t refcnt;
    struct hlist_node node_hlist;
} htbl_node_t;

typedef struct htbl_ops_st {
    void *(*node_create_func)(void);
    int (*node_destroy_func)(void *node);
    int (*node_display_func)(void *node);
    int (*node_hash_func)(void *node);
    int (*meta_hash_func)(void *meta);
    int (*meta_cmp_func)(void *base, void *meta);
    int (*meta_save_func)(void *base, void *meta);
} htbl_ops_t;

typedef struct htbl_ctx_st {
    int nodecnt;
    int bucketcnt;
    htbl_hlist_t *buckets;
    htbl_ops_t *ops;
} htbl_ctx_t;

static inline void *htbl_node_create(htbl_ctx_t *ctx)
{
    if (ctx && ctx->ops && ctx->ops->node_create_func) {
        htbl_node_t *hobj = ctx->ops->node_create_func();
        if (hobj == NULL) {
            return NULL;
        }

        hobj->idx = -1;
        hobj->hval = -1;
        myatomic_init(&hobj->refcnt);
        INIT_HLIST_NODE(&hobj->node_hlist);
        return hobj;
    }

    return NULL;
}

static inline void htbl_node_destroy(htbl_ctx_t *ctx, void *node)
{
    if (ctx && ctx->ops && ctx->ops->node_destroy_func) {
        htbl_node_t *hobj = (htbl_node_t *)node;
        atomic_exit(&hobj->refcnt);
        ctx->ops->node_destroy_func(node);
    }
}

static inline void htbl_node_display(htbl_ctx_t *ctx, void *node)
{
    if (ctx && ctx->ops && ctx->ops->node_display_func) {
        ctx->ops->node_display_func(node);
    }
}

static inline int htbl_node_hash(htbl_ctx_t *ctx, void *node)
{
    uint32_t hval = 0;

    if (ctx && ctx->ops && ctx->ops->node_hash_func) {
        hval = ctx->ops->node_hash_func(node);
        hval = hval % ctx->bucketcnt;
    }

    return hval;
}

static inline void htbl_node_hold(htbl_ctx_t *ctx, void *node)
{
    htbl_node_t *hobj = (htbl_node_t *)node;

    atomic_inc(&hobj->refcnt);
}

static inline void htbl_node_drop(htbl_ctx_t *ctx, void *node)
{
    htbl_node_t *hobj = (htbl_node_t *)node;

    if (atomic_dec_and_test(&hobj->refcnt)){
        htbl_node_destroy(ctx, hobj);
    }
}

static inline int htbl_meta_save(htbl_ctx_t *ctx, void *base, void *meta)
{
    if (ctx && ctx->ops && ctx->ops->meta_save_func) {
        ctx->ops->meta_save_func(base, meta);
        return 0;
    }

    return -EINVAL;
}

static inline int htbl_meta_cmp(htbl_ctx_t *ctx, void *base, void *meta)
{
    if (ctx && ctx->ops && ctx->ops->meta_cmp_func) {
        return ctx->ops->meta_cmp_func(base, meta);
    }

    return -EINVAL;
}

static inline int htbl_meta_hash(htbl_ctx_t *ctx, void *meta)
{
    uint32_t hval = 0;

    if (ctx && ctx->ops && ctx->ops->meta_hash_func) {
        hval = ctx->ops->meta_hash_func(meta);
        hval = hval % ctx->bucketcnt;
    }

    return hval;
}

extern int htbl_init(htbl_ctx_t *ctx);
extern void htbl_fini(htbl_ctx_t *ctx);

extern htbl_ctx_t *htbl_create(int bucketcnt, htbl_ops_t *ops);
extern void htbl_destroy(htbl_ctx_t *ctx);
extern void htbl_display(htbl_ctx_t *ctx);
extern void htbl_clear(htbl_ctx_t *ctx);

extern void *htbl_meta_find(htbl_ctx_t *ctx, void *meta);
extern void *htbl_meta_insert(htbl_ctx_t *ctx, void *meta, int *type);
extern void *htbl_node_insert(htbl_ctx_t *ctx, void *node);
extern int htbl_node_change(htbl_ctx_t *ctx, void *node);
extern int htbl_node_delete(htbl_ctx_t *ctx, void *node);
extern int htbl_meta_delete(htbl_ctx_t *ctx, void *meta);
extern int htbl_meta_deleteall(htbl_ctx_t *ctx, void *meta, int (*cmp)(void *hobj, void *meta));
extern void htbl_foreach(htbl_ctx_t *ctx, int (*handler)(htbl_ctx_t *ctx, void *node, void *arg), void *arg);

#endif
