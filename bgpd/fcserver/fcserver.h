/******************************************************
 * File Name:    bgp_fc.h
 * Author:       basilguo@163.com
 * Created Time: 2023-09-19 02:21:30
 * Description:
 ******************************************************/
#ifndef BGP_FC_H
#define BGP_FC_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <getopt.h>

#include <arpa/inet.h>
#include <netdb.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
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

#include "cJSON.h"
#include "libjhash.h"
#include "libhtable.h"
#include "libncs.h"

typedef uint8_t  u8;
typedef uint16_t  u16;
typedef uint32_t  u32;
typedef uint64_t  u64;

#define IPV4                            4
#define IPV6                            6
#define IP4_LENGTH                      4
#define IP6_LENGTH                      16
#define TCP_PROTO                       0x06

#define FC_VERSION                      1
#define FC_BUFF_SIZE                    1024
#define FC_BUFF_SIZE256                 256
#define FCSRV_HTBL_BUCKETS_SIZE         1023
#define FCSRV_MAX_LINK_AS               256
#define FCSRV_MAX_SRC_PREFIX            256

#define FC_SKI_LENGTH                   20
#define FC_MAX_SIZE                     256

#define FC_HDR_GENERAL_LENGTH           4
#define FC_HDR_FC_FIX_LENGTH            36
#define FC_HDR_BM_FIX_LENGTH            20
#define FC_HDR_BM_SIGLEN_POS            6

#define FC_MSG_BASE                     0
#define FC_MSG_SKI                      (FC_MSG_BASE + 1)
#define FC_MSG_BGPD                     (FC_MSG_BASE + 2)
#define FC_MSG_BC                       (FC_MSG_BASE + 3)

#define FC_DB_NAME                      "/etc/frr/fc.db"
#define FC_NFT_PROG_POS                 "/usr/sbin/nft"

#define FC_ASSERT_RET(ret)                                  \
    do {                                                    \
        if (ret != 0) {                                     \
            fprintf(stderr, "%s:%d error: ret is not 0\n",  \
                    __func__, __LINE__);                    \
        }                                                   \
    } while (0)                                             \

#define FC_ASSERT_RETP(retp)                                    \
    do {                                                        \
        if (pret == 0) {                                        \
            fprintf(stderr, "%s:%d error: pointer is NULL\n",   \
                    __func__, __LINE__);                        \
        }                                                       \
    } while (0)

#define FC_MEM_CHECK(expr)                                      \
    do {                                                        \
        if (expr) {                                             \
            fprintf(stderr, "[%s:%d] ERROR: memory leak\n",     \
                    __func__, __LINE__);                        \
        }                                                       \
    } while (0)



struct prefix {
    uint8_t family;
    uint16_t prefixlen;
    union {
        uint8_t prefix;
        struct in_addr prefix4;
        struct in6_addr prefix6;
        uint8_t val[16];
        uint32_t val32[4];
    } u __attribute__((aligned(8)));
};


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
    struct prefix ipprefix;
    FC_t *fcs;
} FCList_t;

typedef struct FC_ht_node_prefix_s
{
    htbl_node_t hnode; // htbl node must be the first one
    int length;
    int size;
    struct prefix ipprefix;
    FC_t *fcs;
} FC_ht_node_prefix_t;

/* ds-asn-ips */
typedef struct FC_acs_if_s
{
    char ifaddr[INET6_ADDRSTRLEN];
    int ifprefix;
    char ifname[INET6_ADDRSTRLEN];
} FC_acs_if_t;

typedef struct FC_acs_s
{
    int ipv4_num;
    int ipv6_num;
    FC_acs_if_t ipv4[FC_MAX_SIZE];
    FC_acs_if_t ipv6[FC_MAX_SIZE];
} FC_acs_t;

typedef struct FC_ip_s
{
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

extern htbl_ops_t g_fc_htbl_as_ops;
extern htbl_ops_t g_fc_htbl_prefix_ops;

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
    u8 version; // current is 1
    u8 type;    // 1 for pubkey, 2 for bm_bgpd, 3 for bm_broadcast
    u16 length;
} FC_msg_hdr_t;

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
} FC_msg_bm_t;

typedef struct FC_msg_bm_new_s
{
    FC_msg_bm_t *old_bm;
    u8 new_fc_num;
    u8 new_as_num;
    FC_t new_fclist[FCSRV_MAX_LINK_AS];
    u8 new_ski[FC_SKI_LENGTH];
    u8 new_signature[80];
} FC_msg_bm_new_t;

typedef struct FC_server_s
{
    // as-ip totoal num, of course it's as's number
    char *prog_name;
    char *prog_addr;
    u8 asns_num;
    u32 asns[FCSRV_MAX_LINK_AS];
    u32 local_asn;
    /*
       char ipv4[INET_ADDRSTRLEN];
       char ipv6[INET6_ADDRSTRLEN];
       */
    sqlite3 *db;
    htbl_ctx_t ht_as;
    htbl_ctx_t ht_prefix;
    ncs_ctx_t *fc_bgpd_ctx;
    char fname[BUFSIZ];
    FC_node_as_t aps[FCSRV_MAX_LINK_AS];
    EC_KEY *pubkey;
    EC_KEY *prikey;
    int nics_num;
    char nics[FC_MAX_SIZE][20]; // nics
} FC_server_t;

int fc_mask_prefix4 [] = {
    0x00000000, 0x00000001, 0x00000003, 0x00000007, 0x0000000F, 0x0000001F,
    0x0000003F, 0x0000007F, 0x000000FF, 0x000001FF, 0x000003FF, 0x000007FF,
    0x00000FFF, 0x00001FFF, 0x00003FFF, 0x00007FFF, 0x0000FFFF, 0x0001FFFF,
    0x0003FFFF, 0x0007FFFF, 0x000FFFFF, 0x001FFFFF, 0x003FFFFF, 0x007FFFFF,
    0x00FFFFFF, 0x01FFFFFF, 0x03FFFFFF, 0x07FFFFFF, 0x0FFFFFFF, 0x1FFFFFFF,
    0x3FFFFFFF, 0x7FFFFFFF, 0xFFFFFFFF,
};

extern FC_server_t g_fc_server;

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
extern int  fc_read_asn_ips(void);

/* LIBHTABLE */
extern htbl_ops_t g_fc_htbl_as_ops;
extern int fc_hashtable_create(htbl_ctx_t *ht, htbl_ops_t *ops);
extern int fc_hashtable_destroy(htbl_ctx_t *ht);

/* SERVER */
#define FC_PORT 23160
/*
 * #define FC_BGPD_PORT 23160
 * #define FC_BROADCAST_PORT 23161
 * */
extern int fc_main();
extern int fc_server_create(void);
extern void fc_server_destroy(int signum);
extern int fc_server_handler(ncs_ctx_t *ctx);
extern int fc_server_pubkey_handler(ncs_ctx_t *ctx, const char *buff, int bufflen);
extern int fc_server_bm_handler(ncs_ctx_t* ctx, char *buffer, int bufferlen, int msg_type);

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

