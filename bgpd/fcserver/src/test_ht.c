/********************************************************************************
 * File Name:    hashtable_utils.c
 * Author:       basilguo@163.com
 * Created Time: 2023-09-28 01:13:02
 * Description:
 ********************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include "libjhash.h"
#include "libhtable.h"

typedef struct st_s
{
    int i;
} st_t;

typedef struct demo_meta_st {
    int asn;
    int k;
    st_t st;
} demo_meta_t;

typedef struct demo_node_st {
    htbl_node_t hnode; // htbl node must be the first one.
    int asn;
    int k;
    st_t st;
} demo_node_t;

void *demo_node_create(void)
{
    demo_node_t *obj = malloc(sizeof(demo_node_t));
    return obj;
}

int demo_node_destroy(void *node)
{
    free(node);
    return 0;
}

int demo_node_display(void *node)
{
    demo_node_t *obj = (demo_node_t *)node;

    printf("%04d demo %p asn %d\n",
            obj->hnode.idx, obj, obj->asn);

    return 0;
}

static int demo_hash(int asn)
{
    int ret = jhash_1word(asn, 0x19841128);
    printf("hash ret %d\n", ret);
    return ret;
}

int demo_node_hash(void *node)
{
    demo_node_t *nobj = (demo_node_t *)node;

    return demo_hash(nobj->asn);
}

int demo_meta_hash(void *meta)
{
    demo_meta_t *mobj = (demo_meta_t *)meta;

    return demo_hash(mobj->asn);
}

int demo_meta_cmp(void *base, void *meta)
{
    demo_node_t *bobj = (demo_node_t *)base;
    demo_meta_t *mobj = (demo_meta_t *)meta;
    return bobj->asn != mobj->asn;
}

int demo_meta_save(void *base, void *meta)
{
    demo_node_t *bobj = (demo_node_t *)base;
    demo_meta_t *mobj = (demo_meta_t *)meta;
    bobj->asn = mobj->asn;
    bobj->k = mobj->k;
    memcpy(&bobj->st, &mobj->st, sizeof(bobj->st));
    return 0;
}

static htbl_ops_t g_ops_htbl = {
    .node_create_func = demo_node_create,
    .node_destroy_func = demo_node_destroy,
    .node_display_func = demo_node_display,
    .node_hash_func = demo_node_hash,
    .meta_hash_func = demo_meta_hash,
    .meta_cmp_func = demo_meta_cmp,
    .meta_save_func = demo_meta_save,
};

static htbl_ctx_t g_demo_htbl = {
    .bucketcnt = 1023,
    .ops = &g_ops_htbl,
};

int test1()
{
    int i;
    int ret;
    demo_meta_t meta;
    demo_node_t *added;
    demo_node_t *matched;

    meta.asn = 10;

    ret = htbl_init(&g_demo_htbl);
    printf("htbl_init return %d ptr size %d spinlock size %d atomic size %d hlist size %d rwlock size %d hnode size %d node size %d\n",
            ret, (int)sizeof(void *), (int)sizeof(spinlock_t), (int)sizeof(atomic_t),
            (int)sizeof(htbl_hlist_t), (int)sizeof(rwlock_t),
            (int)sizeof(htbl_node_t), (int)sizeof(demo_node_t));

    added = htbl_meta_insert(&g_demo_htbl, &meta, &ret);
    printf("insert 10x12x32 return %p ret %d\n", added, ret);

    added = htbl_meta_insert(&g_demo_htbl, &meta, &ret);
    printf("insert 10x12x32 return %p ret %d\n", added, ret);

    matched = htbl_meta_find(&g_demo_htbl, &meta);
    if (matched) {
        printf("hash matched %d\n", matched->asn);
        htbl_node_drop(&g_demo_htbl, matched);
    }

    /*
    for (i=0; i<1026; i++) {
        meta.asn = i * 20 + 5;
        htbl_meta_insert(&g_demo_htbl, &meta, NULL);
    }
    */

    if (matched) {
        htbl_node_delete(&g_demo_htbl, matched);
        matched = NULL;
    }

    meta.asn = 32;
    matched = htbl_meta_find(&g_demo_htbl, &meta);
    if (matched == NULL) {
        printf("can't match the removed node.\n");
    }

    htbl_display(&g_demo_htbl);

    htbl_fini(&g_demo_htbl);
    return ret;
}

int main(int argc, char *argv[])
{
    test1();
}
