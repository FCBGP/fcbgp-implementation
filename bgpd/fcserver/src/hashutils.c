/********************************************************************************
 * File Name:    hashutils.c
 * Author:       basilguo@163.com
 * Created Time: 2023-12-19 09:08:58
 * Description:  HASHTABLE UTILS
 ********************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include "hashutils.h"
    static void *
fc_as_node_create(void)
{
    FC_ht_node_as_t *node = calloc(1, sizeof(FC_ht_node_as_t));
    return node;
}

    static int
fc_as_node_destroy(void *node)
{
    FC_ht_node_as_t *node_as = (FC_ht_node_as_t *)node;
    EC_KEY_free(node_as->pubkey);
    free(node_as);
    node_as = NULL;
    return 0;
}

    static int
fc_as_node_display(void *node)
{
    int i = 0;
    FC_ht_node_as_t *node_as = (FC_ht_node_as_t *) node;

    printf("asn: %d\n", node_as->asn);
    printf("  acs:\n");
    printf("    ipv4:\n");
    for (i=0; i<node_as->acs.ipv4_num; ++i)
    {
        printf("      ifname: %s\n", node_as->acs.ipv4[i].ifname);
        printf("      ifaddr: %s\n", node_as->acs.ipv4[i].ifaddr);
    }
    printf("    ipv6:\n");
    for (i=0; i<node_as->acs.ipv6_num; ++i)
    {
        printf("      ifname: %s\n", node_as->acs.ipv6[i].ifname);
        printf("      ifaddr: %s\n", node_as->acs.ipv6[i].ifaddr);
    }

    return 0;
}

    static u32
fc_as_hash(u32 asn)
{
    u32 ret = jhash_1word(asn, 0xdeadbeef);
    // printf("ret : %d\n", ret);
    return ret;
}

    static int
fc_as_node_hash(void *node)
{
    FC_ht_node_as_t *node_as = (FC_ht_node_as_t *) node;
    return fc_as_hash(node_as->asn);
}

    static int
fc_as_meta_hash(void *meta)
{
    FC_node_as_t *meta_as = (FC_node_as_t *)meta;
    return fc_as_hash(meta_as->asn);
}

    static int
fc_as_meta_cmp(void *base, void *meta)
{
    FC_ht_node_as_t *node_as = (FC_ht_node_as_t *)base;
    FC_node_as_t *meta_as = (FC_node_as_t *)meta;

    return !!(node_as->asn != meta_as->asn);
}

    static int
fc_as_meta_save(void *base, void *meta)
{
    FC_ht_node_as_t *node_as = (FC_ht_node_as_t *)base;
    FC_node_as_t *meta_as = (FC_node_as_t *)meta;

    node_as->asn = meta_as->asn;
    node_as->pubkey = meta_as->pubkey;
    memcpy(&node_as->acs, &meta_as->acs, sizeof(FC_acs_t));
    memcpy(node_as->cert, meta_as->cert, strlen(meta_as->cert));
    memcpy(node_as->ski, meta_as->ski, FC_SKI_LENGTH);

    return 0;
}

htbl_ops_t g_fc_htbl_as_ops = {
    .node_create_func = fc_as_node_create,
    .node_destroy_func = fc_as_node_destroy,
    .node_display_func = fc_as_node_display,
    .node_hash_func = fc_as_node_hash,
    .meta_hash_func = fc_as_meta_hash,
    .meta_cmp_func = fc_as_meta_cmp,
    .meta_save_func = fc_as_meta_save,
};

    static void *
fc_prefix_node_create(void)
{
    FC_ht_node_prefix_t *node = calloc(1, sizeof(FC_ht_node_prefix_t));
    node->fcs = calloc(FC_MAX_SIZE, sizeof(FC_t));
    return node;
}

    static int
fc_prefix_node_destroy(void *node)
{
    FC_ht_node_prefix_t *node_prefix = (FC_ht_node_prefix_t *)node;
    free(node_prefix->fcs);
    node_prefix->fcs = NULL;
    free(node_prefix);
    node_prefix = NULL;
    return 0;
}

    static int
fc_prefix_hash(struct prefix *prefix)
{
    int i = 0;
    int ret = 0;

    ret = jhash_2words(prefix->family, prefix->prefixlen, 0xdeadbeef);

    for (i=0; i<4; ++i)
        ret = jhash_2words(ret, prefix->u.val32[i], 0xdeadbeef);

    return ret;
}

    static int
fc_prefix_node_hash(void *node)
{
    FC_ht_node_prefix_t *node_prefix = (FC_ht_node_prefix_t *) node;
    return fc_prefix_hash(&node_prefix->ipprefix);
}

    static int
fc_prefix_meta_hash(void *meta)
{
    FCList_t *meta_prefix = (FCList_t *)meta;
    return fc_prefix_hash(&meta_prefix->ipprefix);
}

    static int
fc_prefix_meta_cmp(void *base, void *meta)
{
    FC_ht_node_prefix_t *node_prefix = (FC_ht_node_prefix_t *)base;
    FCList_t *meta_prefix = (FCList_t *)meta;

    int ret = 0; // 0 for equal and 1 for inequal
    int i = 0;

    if (node_prefix->ipprefix.family == meta_prefix->ipprefix.family)
    {
        if (node_prefix->ipprefix.prefixlen == meta_prefix->ipprefix.prefixlen)
        {
            for (i=0; i<4; ++i)
            {
                if (node_prefix->ipprefix.u.val32[i]
                        != meta_prefix->ipprefix.u.val32[i])
                {
                    ret = 1;
                    break;
                }
            }
            return ret;
        }
    }

    return ret;
}

    static int
fc_prefix_meta_save(void *base, void *meta)
{
    FC_ht_node_prefix_t *node_prefix = (FC_ht_node_prefix_t *)base;
    FCList_t *meta_prefix = (FCList_t *)meta;

    node_prefix->size = meta_prefix->size;
    node_prefix->length = meta_prefix->length;
    node_prefix->fcs = meta_prefix->fcs;
    memcpy(&node_prefix->ipprefix, &meta_prefix->ipprefix, sizeof(struct prefix));

    return 0;
}

    static int
fc_prefix_node_display(void *node)
{
    return 0;
}

htbl_ops_t g_fc_htbl_prefix_ops = {
    .node_create_func = fc_prefix_node_create,
    .node_destroy_func = fc_prefix_node_destroy,
    .node_display_func = fc_prefix_node_display,
    .node_hash_func = fc_prefix_node_hash,
    .meta_hash_func = fc_prefix_meta_hash,
    .meta_cmp_func = fc_prefix_meta_cmp,
    .meta_save_func = fc_prefix_meta_save,
};

// 这里需要注意到是，htbl_ops需要是在ht之后不能销毁的
// 所以只能使用g_htbl_ops这种用法了
int fc_hashtable_create(htbl_ctx_t *ht, htbl_ops_t *ops)
{
    int ret = 0;
    ht->bucketcnt = FCSRV_HTBL_BUCKETS_SIZE;
    ht->ops = ops;

    ret = htbl_init(ht);
    FC_ASSERT_RET(ret);
    /*
       printf("htbl_init return %d ptr size %d spinlock size %d atomic size %d hlist size %d rwlock size %d hnode size %d node size %d",
       ret, (int)sizeof(void *), (int)sizeof(spinlock_t), (int)sizeof(atomic_t),
       (int)sizeof(htbl_hlist_t), (int)sizeof(rwlock_t),
       (int)sizeof(htbl_node_t), (int)sizeof(FC_ht_node_as_t));
       */

    return 0;
}

    int
fc_hashtable_destroy(htbl_ctx_t *ht)
{
    if (ht)
    {
        htbl_fini(ht);
        ht = NULL;
    }
    return 0;
}


    static mln_u64_t
ht_aclinfo_hash_handler(mln_hash_t *h, void *key)
{
    return *((u32 *)key) % h->len;
}

    static int
ht_aclinfo_cmp_handler(mln_hash_t *h, void *key1, void *key2)
{
    return !(*((u32 *)key1) - *((u32 *)key2));
}

    static void
ht_aclinfo_free_handler(void *val)
{
    free(val);
}

    int
ht_aclinfo_insert(mln_hash_t *h, u32 iface_index)
{
    static u32 acl_base_index = 3900;
    ht_aclinfo_t *ret = NULL, *item = NULL;

    // 1. search it in ht
    ret = mln_hash_search(h, &iface_index);

    // 2. if not exist, insert it
    if (! ret)
    {
        item = calloc(1, sizeof(ht_aclinfo_t));
        item->iface_index = iface_index;
        item->acl_in_index = acl_base_index;
        item->acl_out_index = acl_base_index + 1;
        acl_base_index += 2;
    }

    return 0;
}

    int
ht_aclinfo_create(mln_hash_t *h)
{
    struct mln_hash_attr hattr;

    hattr.pool = NULL;
    hattr.pool_alloc = NULL;
    hattr.pool_free = NULL;
    hattr.hash = ht_aclinfo_hash_handler;
    hattr.cmp = ht_aclinfo_cmp_handler;
    hattr.key_freer = NULL;
    hattr.val_freer = ht_aclinfo_free_handler;
    hattr.len_base = 47;
    hattr.expandable = 0;
    hattr.calc_prime = 0;

    h = mln_hash_new(&hattr);
    FC_ASSERT_RETP(h);

    return 0;
}

    int
ht_aclinfo_destroy(mln_hash_t *h)
{
    mln_hash_free(h, M_HASH_F_VAL);
    return 0;
}
