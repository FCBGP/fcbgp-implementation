/********************************************************************************
* File Name:    utils.h
* Author:       basilguo@163.com
* Created Time: 2023-09-27 09:27:53
* Description:
********************************************************************************/

#ifndef UTILS_H
#define UTILS_H

#include <sqlite3.h>
#include "common.h"
#include "ds_asn_ip.h"
#include "ds_binding_message.h"
#include "libhtable.h"
#include "libncs.h"

#define ASSERT_RET(ret)                                     \
    do {                                                    \
        if (ret != 0) {                                     \
            fprintf(stderr, "%s:%d error: ret is not 0\n",  \
                    __func__, __LINE__);                    \
        }                                                   \
    } while (0)                                             \

#define ASSERT_RETP(retp)                                       \
    do {                                                        \
        if (pret == 0) {                                        \
            fprintf(stderr, "%s:%d error: pointer is NULL\n",   \
                    __func__, __LINE__);                        \
        }                                                       \
    } while (0)

typedef struct fcserver_s
{
    // as-ip totoal num, of course it's as's number
    u8 asns_num;
    u32 asns[FCSRV_MAX_LINK_AS];
    u32 local_asn;
    sqlite3 *db;
    htbl_ctx_t ht;
    char fname[BUFSIZ];
    node_as_t aps[FCSRV_MAX_LINK_AS];
} fcserver_t;

extern fcserver_t g_fcserver;
extern ncs_ctx_t *bgpd_ctx;
extern ncs_ctx_t *bc_ctx;

/* SIG */
extern int base64_encode(const unsigned char *msg, size_t length, char ** b64msg);
extern int base64_decode(const char *b64msg, unsigned char **msg, size_t *length);

/* JSON */
extern int read_asn_ips();
extern void print_asn_ips();

/* LIBHTABLE */
extern int fcserver_hashtable_create(htbl_ctx_t *ht);
extern int fcserver_hashtable_destroy(htbl_ctx_t *ht);

/* SERVER */
#define FC_BGPD_PORT 23160
#define FC_BROADCAST_PORT 23161
extern int fcserver_create();
extern int fcserver_destroy();
extern void signal_handler(int sig_num);
extern void* broadcast_server_create(void *args);
extern void* bgpd_server_create(void *args);
extern int bm_write_to_db(const fcmsg_bm_t *bm);
extern int bm_handler(char *buffer, int bufferlen, int is_bc);

#endif // UTILS_H
