/********************************************************************************
 * File Name:    hashutils.h
 * Author:       basilguo@163.com
 * Created Time: 2023-12-19 08:57:44
 * Description:  LIBHTABLE
 ********************************************************************************/

#ifndef HASHUTILS_H
#define HASHUTILS_H

#include "libjhash.h"
#include "libhtable.h"
#include "defines.h"

extern htbl_ops_t g_fc_htbl_as_ops;
extern htbl_ops_t g_fc_htbl_prefix_ops;

extern int fc_hashtable_create(htbl_ctx_t *ht, htbl_ops_t *ops);
extern int fc_hashtable_destroy(htbl_ctx_t *ht);

#endif // HASHUTILS_H
