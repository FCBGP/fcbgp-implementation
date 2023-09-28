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

typedef struct fcserver_s
{
    // as-ip totoal num, of course it's as's number
    u8 asns_num;
    u32 asns[FCSRV_MAX_LINK_AS];
    u32 local_asn;
    htbl_ctx_t ht;
    char fname[BUFSIZ];
    node_as_t aps[FCSRV_MAX_LINK_AS];
} fcserver_t;

extern fcserver_t g_fcserver;

/* JSON */
extern int read_asn_ips();
extern void print_asn_ips();

/* LIBHTABLE */
extern int fcserver_hashtable_create(htbl_ctx_t *ht);
extern int fcserver_hashtable_destroy(htbl_ctx_t *ht);

/* DBUTILS */
#define DB_NAME "assets/fc.db"

/* SERVER */
#define FC_BGPD_PORT 23160
#define FC_BROADCAST_PORT 23161
extern int fcserver_create();
extern int fcserver_destroy();
extern int broadcast_server_create();
extern int bgpd_server_create();

#endif // UTILS_H
