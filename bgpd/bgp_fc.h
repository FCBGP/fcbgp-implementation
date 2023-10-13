/******************************************************
 * File Name:    bgp_fc.h
 * Author:       basilguo@163.com
 * Created Time: 2023-09-19 02:21:30
 * Description:
 ******************************************************/
#ifndef BGP_FC_H
#define BGP_FC_H

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <getopt.h>

#include <arpa/inet.h>
#include <netdb.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <signal.h>
#include <time.h>
#include <pthread.h>
#include <unistd.h>

#include <sqlite3.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include "jhash.h"
#include "cJSON.h"
#include "libdiag.h"
#include "libjhash.h"
#include "libhtable.h"
#include "libncs.h"

#include "bgpd/bgpd.h"

typedef uint8_t  u8;
typedef uint16_t  u16;
typedef uint32_t  u32;
typedef uint64_t  u64;

#define IPV4                            4
#define IPV6                            6
#define IP4_LENGTH                      4
#define IP6_LENGTH                      16
#define TCP_PROTO                       0x06

#define FC_BUFF_SIZE                    2048
#define FCSRV_MAX_LINK_AS               256
#define FCSRV_MAX_SRC_PREFIX            256


#define FC_SKI_LENGTH                   20
#define FC_MAX_SIZE                     256

#define FC_HDR_GENERAL_LENGTH           4

#define FC_MSG_BASE                     1000
#define FC_MSG_SKI                      (FC_MSG_BASE + 1)
#define FC_MSG_BGPD                     (FC_MSG_BASE + 2)
#define FC_MSG_BC                       (FC_MSG_BASE + 3)

#define FC_DB_NAME                      "assets/fc.db"

#define FC_ASSERT_RET(ret)                                     \
    do {                                                    \
        if (ret != 0) {                                     \
            fprintf(stderr, "%s:%d error: ret is not 0\n",  \
                    __func__, __LINE__);                    \
        }                                                   \
    } while (0)                                             \

#define FC_ASSERT_RETP(retp)                                       \
    do {                                                        \
        if (pret == 0) {                                        \
            fprintf(stderr, "%s:%d error: pointer is NULL\n",   \
                    __func__, __LINE__);                        \
        }                                                       \
    } while (0)

typedef struct FC_s
{
    u32 previous_asn;
    u32 current_asn; // current asn
    u32 nexthop_asn;
    u8 ski[20];
    u8 algo_id;
    u8 flags;
    u16 siglen;
    u8 sig[80]; // DER format default 64B => ~72B
} FC_t;

typedef struct FCList_s
{
    int length; // length of FCs
    int size; // number of FC in fcs
    struct prefix prefix;
    FC_t fcs[FC_MAX_SIZE];
} FCList_t;

typedef struct FC_node_fclist_s
{
    htbl_node_t hnode; // htbl node must be the first one
    int length;
    int size;
    struct prefix prefix;
    FC_t fcs[FC_MAX_SIZE];
} FC_node_fclist_t;

/* ds-asn-ips */
typedef struct FC_acs_s
{
    char ipv4[INET_ADDRSTRLEN];
    char ipv6[INET6_ADDRSTRLEN];
} FC_acs_t;

typedef struct FC_ip_s
{
    // struct sockaddr ip;
    struct sockaddr ip;
    u8 prefix_length;
} FC_ip_t;

typedef struct FC_prefix_s
{
    int ip4s_num;
    int ip6s_num;
    FC_ip_t ip4s[FCSRV_MAX_SRC_PREFIX];
    FC_ip_t ip6s[FCSRV_MAX_SRC_PREFIX];
} FC_prefix_t;

typedef struct FC_asn_ip_s
{
    FC_acs_t acs;
    FC_prefix_t prefix;
} FC_asn_ip_t;

// for hashtable meta
typedef struct FC_node_as_s
{
    u32 asn;
    FC_asn_ip_t ap;
} FC_node_as_t;

extern htbl_ops_t g_htbl_ops = {
    .node_create_func = fc_as_node_create,
    .node_destroy_func = fc_as_node_destroy,
    .node_display_func = fc_as_node_display,
    .node_hash_func = fc_as_node_hash,
    .meta_hash_func = fc_as_meta_hash,
    .meta_cmp_func = fc_as_meta_cmp,
    .meta_save_func = fc_as_meta_save,
};


// for hashtable node
typedef struct FC_ht_node_as_s
{
    htbl_node_t hnode; // htbl node must be the first one
    u32 asn;
    FC_asn_ip_t ap;
} FC_ht_node_as_t;

/* ds-binding-message */
typedef struct FC_msg_hdr_st
{
    u8 type; // 1 for pubkey, 2 for bm
    u16 length;
    u8 reserved;
} __attribute__((packed)) FC_msg_hdr_t;

typedef struct FC_msg_bm_st
{
    u8 ipversion;       // 1 for ipv4, 2 for ipv6
    u8 type;            // 0 for onpath nodes, 1 for offpath
    u8 action;          // 0 for add/update, 1 for del/withdraw
    u8 fc_num;          // num of fc in fclist, boundary
    u8 src_ip_num;      // src ip prefix num, boundary
    u8 dst_ip_num;      // dst ip prefix num, boundary
    u16 siglen;
    u32 local_asn;      // local as number
    u32 version;
    u32 subversion;
    FC_ip_t src_ip[FCSRV_MAX_SRC_PREFIX];
    FC_ip_t dst_ip[FCSRV_MAX_SRC_PREFIX];
    FC_t fclist[FCSRV_MAX_LINK_AS];
    u8 ski[FC_SKI_LENGTH];
    u8 signature[80];
} __attribute__((packed)) FC_msg_bm_t;

typedef struct FC_msg_bm_new_s
{
    FC_msg_bm_t *old_bm;
    u8 new_fc_num;
    u8 new_as_num;
    FC_t new_fclist[FCSRV_MAX_LINK_AS];
    u8 new_ski[FC_SKI_LENGTH];
    u8 new_signature[80];
} __attribute__((packed)) FC_msg_bm_new_t;

typedef struct FC_server_s
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
    FC_node_as_t aps[FCSRV_MAX_LINK_AS];
    EC_KEY *pubkey;
    EC_KEY *prikey;
} FC_server_t;

extern FC_server_t g_fc_server;
extern ncs_ctx_t *fc_bgpd_ctx;

/* SIG */
extern int fc_init_crypto_env(FC_server_t *fcserver);
extern int fc_read_eckey_from_file(int is_pub_key, EC_KEY **pkey);
extern int fc_base64_encode(const unsigned char *msg,
        size_t length, char * b64msg);
extern int fc_base64_decode(const char *b64msg, unsigned char **msg,
        size_t *length);
extern int fc_ecdsa_sign(EC_KEY *prikey, const char *const msg, int msglen,
        unsigned char **sigbuff, unsigned int *siglen);
extern int fc_ecdsa_verify(EC_KEY *pubkey, const char *const msg, int msglen,
        const unsigned char *sigbuff, unsigned int siglen);

/* JSON */
extern int  fc_read_asn_ips();
extern void fc_print_asn_ips();

/* LIBHTABLE */
extern int fc_hashtable_create(htbl_ctx_t *ht);
extern int fc_hashtable_destroy(htbl_ctx_t *ht);

/* SERVER */
#define FC_PORT 23160
/*
 * #define FC_BGPD_PORT 23160
 * #define FC_BROADCAST_PORT 23161
 * */
extern int fc_server_create();
extern int fc_server_destroy();
extern void fc_server_signal_handler(int sig_num);
extern int fc_server_handler(ncs_ctx_t *ctx);
extern int fc_server_pubkey_handler(const char *buff, int bufflen);
extern int fc_server_bm_handler(char *buffer, int bufferlen, int msg_type);

/* DB UTILS */
extern int fc_db_open(sqlite3 **db, const char *dbname);
extern int fc_db_close(sqlite3 *db);
extern void fc_init_db(sqlite3 **db);
extern int fc_db_store_bm_handler(void *data, int argc, char **argv,
        char **az_col_name);
extern int fc_db_select_bm_handler(void *data, int argc, char **argv,
        char **az_col_name);
extern int fc_db_write_bm(const FC_msg_bm_t *bm);
extern int fc_db_exec(sqlite3 *db, const char *sql,
        int (*cb)(void *data, int argc, char **argv, char **az_col_name),
        void *data);


/*
 * hton: ip
 * */
/*
extern int fc_prefix_to_ip_hton_format(afi_t afi, char *buff, int bufflen);
extern int fc_send_packet_to_fcserver(char *buff, int bufflen);
*/

#endif // BGP_FC_H

