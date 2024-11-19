/********************************************************************************
 * File Name:    hashutils.h
 * Author:       basilguo@163.com
 * Created Time: 2023-12-19 08:57:44
 * Description:  LIBHTABLE
 ********************************************************************************/

#ifndef HASHUTILS_H
#define HASHUTILS_H

#include "defines.h"
#include "libhtable.h"
#include "libjhash.h"
#include "uthash.h"

extern htbl_ops_t g_fc_htbl_as_ops;
extern htbl_ops_t g_fc_htbl_prefix_ops;

extern int fc_hashtable_create(htbl_ctx_t *ht, htbl_ops_t *ops);
extern int fc_hashtable_destroy(htbl_ctx_t *ht);
extern int ht_aclinfo_create(ht_acl_group_info_t **h);
extern int ht_aclinfo_destroy(ht_acl_group_info_t *h);
extern int ht_aclinfo_insert(ht_acl_group_info_t *h,
                             u32 iface_index,
                             FC_router_info_t *target_router);
extern u32 fnv1a_hash(const void *data, size_t len);

#endif // HASHUTILS_H
