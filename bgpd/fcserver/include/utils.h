/********************************************************************************
* File Name:    utils.h
* Author:       basilguo@163.com
* Created Time: 2023-09-27 09:27:53
* Description:
********************************************************************************/

#ifndef UTILS_H
#define UTILS_H

#include "common.h"
#include "ds_asn_ip.h"
#include "libhtable.h"

/* JSON */
extern int read_asn_ips(const char *fname, fcserver_t *fcserver,
        htbl_ctx_t *h, int *asns, int *asns_size);
extern void print_asn_ips(htbl_ctx_t *ht, int *asns, int asns_size);

/* LIBHTABLE */
extern int create_fcserver_hashtable(htbl_ctx_t *ht);
extern int destroy_fcserver_hashtable(htbl_ctx_t *ht);

#endif // UTILS_H
