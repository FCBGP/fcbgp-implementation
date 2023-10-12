/********************************************************************************
* File Name:    bgp_util.h
* Author:       basilguo@163.com
* Created Time: 2023-09-21 03:26:08
* Description:
********************************************************************************/

#ifndef BGP_UTIL_H
#define BGP_UTIL_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include "libhtable.h"
#include "lib/zlog.h"
#include "bgpd/bgp_config.h"

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
    /*
       char ipv4[INET_ADDRSTRLEN];
       char ipv6[INET6_ADDRSTRLEN];
       */
    sqlite3 *db;
    htbl_ctx_t ht;
    char fname[BUFSIZ];
    node_as_t aps[FCSRV_MAX_LINK_AS];
    EC_KEY *pubkey;
    EC_KEY *prikey;
} fcserver_t;

extern fcserver_t g_fcserver;
extern ncs_ctx_t *bgpd_ctx;

/* SIG */
extern int fc_init_crypto_env(fcserver_t *fcserver);
extern int fc_read_eckey_from_file(int is_pub_key, EC_KEY **pkey);
extern int fc_base64_encode(const unsigned char *msg, size_t length,
                char * b64msg);
extern int fc_base64_decode(const char *b64msg, unsigned char **msg,
                size_t *length);
extern int fc_ecdsa_sign(EC_KEY *prikey, const char *const msg,
                unsigned char **sigbuff, unsigned int *siglen);
extern int fc_ecdsa_verify(EC_KEY *pubkey, const char *const msg,
                const unsigned char *sigbuff, unsigned int siglen);

/* JSON */
extern int  fc_read_asn_ips();
extern void fc_print_asn_ips();

/* LIBHTABLE */
extern int fcserver_hashtable_create(htbl_ctx_t *ht);
extern int fcserver_hashtable_destroy(htbl_ctx_t *ht);

/* SERVER */
#define FC_PORT 23160
/*
 * #define FC_BGPD_PORT 23160
 * #define FC_BROADCAST_PORT 23161
 * */
extern int fcserver_create();
extern int fcserver_destroy();
extern void fc_signal_handler(int sig_num);
extern void* fc_broadcast_server_create(void *args);
extern void* fc_bgpd_server_create(void *args);
extern int fc_bm_write_to_db(const fcmsg_bm_t *bm);
extern int fc_bm_handler(char *buffer, int bufferlen, int msg_type);


extern int fc_db_open(sqlite3 **db, const char *dbname);
extern int fc_db_store_bm_handler(void *data, int argc, char **argv,
                char **az_col_name);
extern int fc_db_select_bm_handler(void *data, int argc, char **argv,
                char **az_col_name);
int fc_db_exec(sqlite3 *db, const char *sql,
                int (*cb)(void *data, int argc, char **argv, char **az_col_name),
                        void *data);
int fc_db_close(sqlite3 *db);
void fc_init_db(sqlite3 **db);


static int sha256(const unsigned char * const msg, unsigned char *digest,
        unsigned int *digest_len)
{
    int i = 0;
    const EVP_MD *md = NULL;
    EVP_MD_CTX *mdctx = NULL;

    if ((md = EVP_get_digestbyname("sha256")) == NULL)
    {
        fprintf(stderr, "Unknown message digest\n");
        exit(EXIT_FAILURE);
    }

    if ((mdctx = EVP_MD_CTX_new()) == NULL)
    {
        fprintf(stderr, "create md ctx failed\n");
        exit(EXIT_FAILURE);
    }

    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, msg, strlen(msg));
    EVP_DigestFinal_ex(mdctx, digest, digest_len);
    EVP_MD_CTX_free(mdctx);

    zlog_debug("Digest len is : %u", *digest);
    char log_msg[BUFSIZ] = {0};
    for (i=0; i<*digest_len; ++i)
    {
        snprintf(log_msg[i*2], BUFSIZ, "%02x", digest[i]);
    }
    zlog_debug("Digest is : %s", log_msg);

    return 0;
}

#endif // BGP_UTIL_H
