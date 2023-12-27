/********************************************************************************
 * File Name:    defines.h
 * Author:       basilguo@163.com
 * Created Time: 2023-12-19 09:37:53
 * Description:  definitions
 ********************************************************************************/

#ifndef DEFINES_H
#define DEFINES_H

#include <arpa/inet.h>

#include <sqlite3.h>
#include <openssl/ec.h>

#include "libhtable.h"
#include "libncs6.h"

#define STR(x) #x
#define FC_MAJOR_VERSION STR(0)
#define FC_MINOR_VERSION STR(1)
#define FC_PATCH_VERSION STR(3)
#define FC_PRJ_VERSION FC_MAJOR_VERSION "." \
    FC_MINOR_VERSION "." FC_PATCH_VERSION
#define FC_VERSION_STR "FC Server V" FC_PRJ_VERSION \
    " compiled at " __DATE__ " " __TIME__ ""
#define FC_SSL_VERSION "OpenSSL 3.0.2 15 Mar 2022"

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

#define FC_DB_NAME                      "/etc/frr/assets/fc.db"
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
    u8 prefix_length;
    struct sockaddr ip;
} FC_ip_t;

// for hashtable meta
typedef struct FC_node_as_s
{
    u32 asn;
    char cert[FC_MAX_SIZE];
    u8 ski[FC_SKI_LENGTH];
    EC_KEY *pubkey;
    FC_acs_t acs;
} FC_node_as_t;

// for hashtable node
typedef struct FC_ht_node_as_s
{
    htbl_node_t hnode; // htbl node must be the first one
    u32 asn;
    char cert[FC_MAX_SIZE];
    u8 ski[FC_SKI_LENGTH];
    EC_KEY *pubkey;
    FC_acs_t acs;
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
    char *prog_addr4;
    char *prog_addr6;
    u8 log_mode;
    u8 clear_fc_db;
    u32 local_asn;
    u8 asns_num;
    u32 asns[FCSRV_MAX_LINK_AS];
    sqlite3 *db;
    htbl_ctx_t ht_as;
    htbl_ctx_t ht_prefix;
    ncs6_ctx_t *fc_bgpd_ctx6;
    char *config_fname;
    char *prikey_fname;
    char *certs_location;
    FC_node_as_t aps[FCSRV_MAX_LINK_AS];
    EC_KEY *pubkey;
    EC_KEY *prikey;
    int nics_num;
    char nics[FC_MAX_SIZE][20]; // nics
} FC_server_t;

extern FC_server_t g_fc_server;

#endif // DEFINES_H
