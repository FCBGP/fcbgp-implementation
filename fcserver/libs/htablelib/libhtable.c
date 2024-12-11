#include "libhtable.h"
#include "libdiag.h"

void* htbl_meta_find(htbl_ctx_t* ctx, void* meta)
{
    struct hlist_node* pos;
    htbl_node_t* hobj = NULL;
    int hval = htbl_meta_hash(ctx, meta);
    htbl_hlist_t* hlist = ctx->buckets + hval;

    rwlock_rdlock(&hlist->rwlock);
    hlist_for_each_entry(hobj, pos, &hlist->head, node_hlist)
    {
        if (htbl_meta_cmp(ctx, hobj, meta) == 0)
        {
            htbl_node_hold(ctx, hobj);
            rwlock_rdunlock(&hlist->rwlock);
            return hobj;
        }
    }
    rwlock_rdunlock(&hlist->rwlock);

    return NULL;
}

void* htbl_meta_insert(htbl_ctx_t* ctx, void* meta, int* type)
{
    htbl_node_t* hobj = NULL;

    if (type)
    {
        hobj = htbl_meta_find(ctx, meta);
        if (hobj)
        {
            htbl_node_drop(ctx, hobj);
            *type = 1;
            return hobj;
        }
        *type = 0;
    }

    hobj = htbl_node_create(ctx);
    if (hobj == NULL)
    {
        return NULL;
    }

    int hval = htbl_meta_hash(ctx, meta);
    htbl_hlist_t* hlist = ctx->buckets + hval;

    rwlock_wrlock(&hlist->rwlock);
    hlist_add_head(&hobj->node_hlist, &hlist->head);
    htbl_node_hold(ctx, hobj);
    hobj->hval = hval;
    hobj->idx = ctx->nodecnt;
    hlist->nodecnt++;
    hlist->changes++;
    rwlock_wrunlock(&hlist->rwlock);

    htbl_meta_save(ctx, hobj, meta);
    ctx->nodecnt++;
    return hobj;
}

void* htbl_node_insert(htbl_ctx_t* ctx, void* node)
{
    htbl_node_t* hobj = (htbl_node_t*)node;

    int hval = htbl_node_hash(ctx, node);
    htbl_hlist_t* hlist = ctx->buckets + hval;

    rwlock_wrlock(&hlist->rwlock);
    hlist_add_head(&hobj->node_hlist, &hlist->head);
    htbl_node_hold(ctx, hobj);
    hobj->hval = hval;
    hobj->idx = ctx->nodecnt;
    hlist->nodecnt++;
    rwlock_wrunlock(&hlist->rwlock);

    ctx->nodecnt++;
    return hobj;
}

int htbl_node_change(htbl_ctx_t* ctx, void* node)
{
    htbl_node_t* hobj = (htbl_node_t*)node;
    htbl_hlist_t* hlist = ctx->buckets + hobj->hval;

    rwlock_wrlock(&hlist->rwlock);
    hlist->changes++;
    rwlock_wrunlock(&hlist->rwlock);

    return hlist->changes;
}

int htbl_node_delete(htbl_ctx_t* ctx, void* node)
{
    htbl_node_t* hobj = (htbl_node_t*)node;
    htbl_hlist_t* hlist = ctx->buckets + hobj->hval;

    rwlock_wrlock(&hlist->rwlock);
    hlist_del(&hobj->node_hlist);
    htbl_node_drop(ctx, hobj);
    hlist->nodecnt--;
    hlist->changes++;
    rwlock_wrunlock(&hlist->rwlock);

    ctx->nodecnt--;
    return 0;
}

int htbl_meta_delete(htbl_ctx_t* ctx, void* meta)
{
    htbl_node_t* hobj = NULL;
    struct hlist_node *pos, *tpos;
    int hval = htbl_meta_hash(ctx, meta);
    htbl_hlist_t* hlist = ctx->buckets + hval;

    rwlock_wrlock(&hlist->rwlock);
    hlist_for_each_entry_safe(hobj, pos, tpos, &hlist->head, node_hlist)
    {
        if (htbl_meta_cmp(ctx, hobj, meta) == 0)
        {
            hlist_del(&hobj->node_hlist);
            htbl_node_drop(ctx, hobj);
            hlist->nodecnt--;
            hlist->changes++;

            htbl_node_drop(ctx, hobj);
            rwlock_wrunlock(&hlist->rwlock);
            return 0;
        }
    }
    rwlock_wrunlock(&hlist->rwlock);

    return -ENOENT;
}

int htbl_meta_deleteall(htbl_ctx_t* ctx, void* meta,
                        int (*cmp)(void* hobj, void* meta))
{
    int i = 0;
    int cnt = 0;
    htbl_node_t* hobj = NULL;
    htbl_hlist_t* hlist = NULL;
    struct hlist_node *pos, *tpos;

    for (i = 0; i < ctx->bucketcnt; i++)
    {
        hlist = ctx->buckets + i;
        rwlock_wrlock(&hlist->rwlock);
        hlist_for_each_entry_safe(hobj, pos, tpos, &hlist->head, node_hlist)
        {
            if (cmp && cmp(hobj, meta) == 0)
            {
                hlist_del(&hobj->node_hlist);
                htbl_node_drop(ctx, hobj);
                hlist->nodecnt--;
                hlist->changes++;
                cnt++;
            }
        }
        rwlock_wrunlock(&hlist->rwlock);
    }

    return cnt;
}

int htbl_init(htbl_ctx_t* ctx)
{
    int i;

    if (ctx->ops->meta_save_func == NULL)
    {
        return -EINVAL;
    }

    if (ctx->bucketcnt == 0 || ctx->ops->meta_hash_func == NULL ||
        ctx->ops->meta_cmp_func == NULL)
    {
        return -EINVAL;
    }

    ctx->buckets = malloc(ctx->bucketcnt * sizeof(htbl_hlist_t));
    if (ctx->buckets == NULL)
    {
        return -ENOMEM;
    }

    for (i = 0; i < ctx->bucketcnt; i++)
    {
        htbl_hlist_t* hlist = ctx->buckets + i;

        hlist->changes = 0;
        hlist->nodecnt = 0;
        rwlock_init(&hlist->rwlock);
        INIT_HLIST_HEAD(&hlist->head);
    }

    ctx->nodecnt = 0;
    return 0;
}

void htbl_display(htbl_ctx_t* ctx)
{
    int i;
    int maxnodecnt = 0;
    int bucket_used = 0;
    struct hlist_node* pos;
    htbl_node_t* hobj = NULL;

    if (ctx == NULL)
    {
        return;
    }

    int minnodecnt = ctx->nodecnt;
    for (i = 0; i < ctx->bucketcnt; i++)
    {
        htbl_hlist_t* hlist = ctx->buckets + i;

        if (hlist->nodecnt)
        {
            DIAG_INFO("%p: --%04d-- nodes %d changes %d:\n", ctx, i,
                      hlist->nodecnt, hlist->changes);
            hlist_for_each_entry(hobj, pos, &hlist->head, node_hlist)
            {
                htbl_node_display(ctx, hobj);
            }

            if (minnodecnt > hlist->nodecnt)
            {
                minnodecnt = hlist->nodecnt;
            }

            if (maxnodecnt < hlist->nodecnt)
            {
                maxnodecnt = hlist->nodecnt;
            }

            bucket_used++;
        }
    }

    DIAG_INFO("%p: nodecnt %d min nodecnt %d max nodecnt %d bucketused %d "
              "bucketcnt %d\n",
              ctx, ctx->nodecnt, minnodecnt, maxnodecnt, bucket_used,
              ctx->bucketcnt);
}

void htbl_foreach(htbl_ctx_t* ctx,
                  int (*handler)(htbl_ctx_t* ctx, void* node, void* arg),
                  void* arg)
{
    int i;
    struct hlist_node* pos;
    htbl_node_t* hobj = NULL;

    if (ctx == NULL || handler == NULL)
    {
        return;
    }

    for (i = 0; i < ctx->bucketcnt; i++)
    {
        htbl_hlist_t* hlist = ctx->buckets + i;

        rwlock_rdlock(&hlist->rwlock);
        hlist_for_each_entry(hobj, pos, &hlist->head, node_hlist)
        {
            handler(ctx, hobj, arg);
        }
        rwlock_rdunlock(&hlist->rwlock);
    }
}

void htbl_clear(htbl_ctx_t* ctx)
{
    int i;
    htbl_node_t* node;
    struct hlist_node *nnode, *tnode;

    for (i = 0; i < ctx->bucketcnt; i++)
    {
        htbl_hlist_t* hlist = ctx->buckets + i;

        rwlock_wrlock(&hlist->rwlock);
        hlist_for_each_entry_safe(node, nnode, tnode, &hlist->head, node_hlist)
        {
            hlist_del(&node->node_hlist);
            htbl_node_drop(ctx, node);
            hlist->changes++;
        }
        hlist->nodecnt = 0;
        rwlock_wrunlock(&hlist->rwlock);
    }

    ctx->nodecnt = 0;
    return;
}

void htbl_fini(htbl_ctx_t* ctx)
{
    int i;
    htbl_node_t* node;
    struct hlist_node *nnode, *tnode;

    for (i = 0; i < ctx->bucketcnt; i++)
    {
        htbl_hlist_t* hlist = ctx->buckets + i;

        rwlock_wrlock(&hlist->rwlock);
        hlist_for_each_entry_safe(node, nnode, tnode, &hlist->head, node_hlist)
        {
            hlist_del(&node->node_hlist);
            htbl_node_drop(ctx, node);
        }
        rwlock_wrunlock(&hlist->rwlock);

        rwlock_destroy(&hlist->rwlock);
    }

    free(ctx->buckets);
    ctx->buckets = NULL;

    return;
}

htbl_ctx_t* htbl_create(int bucketcnt, htbl_ops_t* ops)
{
    htbl_ctx_t* ctx = malloc(sizeof(htbl_ctx_t));
    if (ctx == NULL)
    {
        return NULL;
    }

    ctx->ops = ops;
    ctx->bucketcnt = bucketcnt;

    if (htbl_init(ctx) < 0)
    {
        free(ctx);
        return NULL;
    }

    return ctx;
}

void htbl_destroy(htbl_ctx_t* ctx)
{
    if (ctx)
    {
        htbl_fini(ctx);
        free(ctx);
    }
}
