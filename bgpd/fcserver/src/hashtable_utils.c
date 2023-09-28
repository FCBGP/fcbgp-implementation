/********************************************************************************
 * File Name:    hashtable_utils.c
 * Author:       basilguo@163.com
 * Created Time: 2023-09-28 01:25:35
 * Description:
 ********************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include "libjhash.h"
#include "libhtable.h"
#include "utils.h"

void * demo_node_create(void)
{
    ht_node_as_t *node = malloc(sizeof(ht_node_as_t));
    return node;
}

int demo_node_destroy(void *node)
{
    free(node);
    return 0;
}

int demo_node_display(void *node)
{
    char ipstr[INET6_ADDRSTRLEN] = {0};
    int i = 0;
    ht_node_as_t *node_as = (ht_node_as_t *) node;

    printf("asn: %d\n", node_as->asn);
    printf("  acs:\n");
    printf("    ipv4: %s\n", node_as->ap.acs.ipv4);
    printf("    ipv6: %s\n", node_as->ap.acs.ipv6);
    printf("  prefix:\n");
    for (i=0; i<node_as->ap.prefix.ip4s_num; ++i)
    {
        inet_ntop(AF_INET, &node_as->ap.prefix.ip4s[i].ip,
                ipstr, (socklen_t)sizeof(ipstr));
        printf("    ipv4: %s/%d\n",
                ipstr, node_as->ap.prefix.ip4s[i].prefix_length);
    }
    for (i=0; i<node_as->ap.prefix.ip6s_num; ++i)
    {
        inet_ntop(AF_INET6, &node_as->ap.prefix.ip6s[i].ip,
                ipstr, (socklen_t)sizeof(ipstr));
        printf("    ipv6: %s/%d\n",
                ipstr, node_as->ap.prefix.ip6s[i].prefix_length);
    }

    return 0;
}

static int demo_hash(u32 asn)
{
    int ret = jhash_1word(asn, 0x19841128);
    // printf("ret : %d\n", ret);
    return ret;
}

int demo_node_hash(void *node)
{
    ht_node_as_t *node_as = (ht_node_as_t *) node;
    return demo_hash(node_as->asn);
}

int demo_meta_hash(void *meta)
{
    node_as_t *meta_as = (node_as_t *)meta;
    return demo_hash(meta_as->asn);
}

int demo_meta_cmp(void *base, void *meta)
{
    ht_node_as_t *node_as = (ht_node_as_t *)base;
    node_as_t *meta_as = (node_as_t *)meta;

    return !!(node_as->asn != meta_as->asn);
}

int demo_meta_save(void *base, void *meta)
{
    ht_node_as_t *node_as = (ht_node_as_t *)base;
    node_as_t *meta_as = (node_as_t *)meta;

    node_as->asn = meta_as->asn;
    memcpy(&node_as->ap, &meta_as->ap, sizeof(asn_ip_t));

    return 0;
}

static htbl_ops_t g_htbl_ops = {
    .node_create_func = demo_node_create,
    .node_destroy_func = demo_node_destroy,
    .node_display_func = demo_node_display,
    .node_hash_func = demo_node_hash,
    .meta_hash_func = demo_meta_hash,
    .meta_cmp_func = demo_meta_cmp,
    .meta_save_func = demo_meta_save,
};

// 这里需要注意到是，htbl_ops需要是在ht之后不能销毁的
// 所以只能使用g_htbl_ops这种用法了
int fcserver_hashtable_create(htbl_ctx_t *ht)
{
    int ret = 0;


    ht->bucketcnt = FCSRV_MAX_LINK_AS;
    ht->ops = &g_htbl_ops;

    ret = htbl_init(ht);
    printf("htbl_init return %d ptr size %d spinlock size %d atomic size %d hlist size %d rwlock size %d hnode size %d node size %d\n",
            ret, (int)sizeof(void *), (int)sizeof(spinlock_t), (int)sizeof(atomic_t),
            (int)sizeof(htbl_hlist_t), (int)sizeof(rwlock_t),
            (int)sizeof(htbl_node_t), (int)sizeof(ht_node_as_t));

    return 0;
}

int fcserver_hashtable_destroy(htbl_ctx_t *ht)
{
    htbl_fini(ht);
    return 0;
}

#ifdef TEST_MAIN
int main(void)
{
    int i;
    int ret;
    ht_node_as_t *added, *matched;
    node_as_t meta;
    meta.asn = 10;
    htbl_ops_t htbl_ops = {
        .node_create_func = demo_node_create,
        .node_destroy_func = demo_node_destroy,
        .node_display_func = demo_node_display,
        .node_hash_func = demo_node_hash,
        .meta_hash_func = demo_meta_hash,
        .meta_cmp_func = demo_meta_cmp,
        .meta_save_func = demo_meta_save,
    };

    htbl_ctx_t ht = {
        .bucketcnt = FCSRV_MAX_LINK_AS,
        .ops = &htbl_ops,
    };

    htbl_init(&ht);
    printf("htbl_init return %d ptr size %d spinlock size %d atomic size %d hlist size %d rwlock size %d hnode size %d node size %d\n",
            ret, (int)sizeof(void *), (int)sizeof(spinlock_t), (int)sizeof(atomic_t),
            (int)sizeof(htbl_hlist_t), (int)sizeof(rwlock_t),
            (int)sizeof(htbl_node_t), (int)sizeof(ht_node_as_t));

    added = htbl_meta_insert(&ht, &meta, &ret);
    printf("insert asn=10 return %p ret %d\n", added, ret);

    destroy_fcserver_hashtable(&ht);

    return 0;
}
#endif
