/********************************************************************************
 * File Name:    hashutils.c
 * Author:       basilguo@163.com
 * Created Time: 2023-12-19 09:08:58
 * Description:  HASHTABLE UTILS
 ********************************************************************************/

#include "hashutils.h"
#include "libdiag.h"
#include "sysconfig.h"
#include <stdio.h>
#include <stdlib.h>

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
    FC_ht_node_as_t *node_as = (FC_ht_node_as_t *)node;

    DIAG_INFO("asn: %d\n", node_as->asn);
    DIAG_INFO("  acs:\n");
    DIAG_INFO("    ipv4:\n");
    for (i = 0; i < node_as->acs.ipv4_num; ++i)
    {
        DIAG_INFO("      ifname: %s\n", node_as->acs.ipv4[i].ifname);
        DIAG_INFO("      ifaddr: %s\n", node_as->acs.ipv4[i].ifaddr);
    }
    DIAG_INFO("    ipv6:\n");
    for (i = 0; i < node_as->acs.ipv6_num; ++i)
    {
        DIAG_INFO("      ifname: %s\n", node_as->acs.ipv6[i].ifname);
        DIAG_INFO("      ifaddr: %s\n", node_as->acs.ipv6[i].ifaddr);
    }

    return 0;
}

static u32
fc_as_hash(u32 asn)
{
    u32 ret = jhash_1word(asn, 0xdeadbeef);
    // DIAG_INFO("ret : %d\n", ret);
    return ret;
}

static int
fc_as_node_hash(void *node)
{
    FC_ht_node_as_t *node_as = (FC_ht_node_as_t *)node;
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

    for (i = 0; i < 4; ++i)
        ret = jhash_2words(ret, prefix->u.val32[i], 0xdeadbeef);

    return ret;
}

static int
fc_prefix_node_hash(void *node)
{
    FC_ht_node_prefix_t *node_prefix = (FC_ht_node_prefix_t *)node;
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
            for (i = 0; i < 4; ++i)
            {
                if (node_prefix->ipprefix.u.val32[i] != meta_prefix->ipprefix.u.val32[i])
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
       DIAG_INFO("htbl_init return %d ptr size %d spinlock size %d atomic size %d hlist size %d rwlock size %d hnode size %d node size %d",
       ret, (int)sizeof(void *), (int)sizeof(spinlock_t), (int)sizeof(atomic_t),
       (int)sizeof(htbl_hlist_t), (int)sizeof(rwlock_t),
       (int)sizeof(htbl_node_t), (int)sizeof(FC_ht_node_as_t));
       */

    return 0;
}

int fc_hashtable_destroy(htbl_ctx_t *ht)
{
    if (ht)
    {
        htbl_fini(ht);
        ht = NULL;
    }
    return 0;
}

int ht_aclinfo_insert(ht_acl_group_info_t *ht,
                      u32 iface_index,
                      FC_router_info_t *target_router)
{
    ht_acl_group_info_t *acl_group_info = NULL, *item = NULL;

    FC_ASSERT_RETP(ht);

    // 1. search it in ht
    HASH_FIND_INT(ht, &iface_index, acl_group_info);

    // 2. if not exist, insert it
    if (!acl_group_info)
    {
        item = calloc(1, sizeof(ht_acl_group_info_t));
        item->iface_index = iface_index;
        item->acl_group_index = ++target_router->acl_group_index;
        HASH_ADD_INT(ht, iface_index, item);
    }

    return 0;
}

int ht_aclinfo_create(ht_acl_group_info_t **ht)
{
    (void)ht;
    return 0;
}

int ht_aclinfo_destroy(ht_acl_group_info_t *ht)
{
    ht_acl_group_info_t *acl_group_info = NULL, *tmp = NULL;
    HASH_ITER(hh, ht, acl_group_info, tmp)
    {
        HASH_DEL(ht, acl_group_info);
        free(acl_group_info);
    }

    return 0;
}

u32 fnv1a_hash(const void *data, size_t len)
{
    u32 hash = 2166136261u; // FNV-1a initial value
    const unsigned char *p = (const unsigned char *)data;

    for (size_t i = 0; i < len; i++)
    {
        hash ^= p[i];     // XOR
        hash *= 16777619; // multiply FNV constant
    }

    return hash;
}
