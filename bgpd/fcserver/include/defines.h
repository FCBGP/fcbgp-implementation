/********************************************************************************
 * File Name:    defines.h
 * Author:       basilguo@163.com
 * Created Time: 2023-12-19 09:37:53
 * Description:  definitions
 ********************************************************************************/

#ifndef DEFINES_H
#define DEFINES_H

#include "libdiag.h"
#include "libhtable.h"
#include "pyutils.h"
#include "strutils.h"
#include "sysconfig.h"
#include "utarray.h"
#include "uthash.h"
#include <Python.h>
#include <arpa/inet.h>
#include <openssl/ec.h>
#include <pthread.h>
#include <sqlite3.h>
#include <stdbool.h>
#include <sys/epoll.h>

#define STR(x) #x
#define FC_MAJOR_VERSION STR(0)
#define FC_MINOR_VERSION STR(2)
#define FC_PATCH_VERSION STR(6)
#define FC_PRJ_VERSION FC_MAJOR_VERSION "." FC_MINOR_VERSION "." FC_PATCH_VERSION
#define FC_VERSION_STR "FC Server V" FC_PRJ_VERSION \
                       " compiled at " __DATE__ " " __TIME__ ""

#define FC_BUFF_SIZE 1000007
#define FC_BUFF_SIZE256 256
#define FCSRV_HTBL_BUCKETS_SIZE 1000007
#define FCSRV_MAX_LINK_AS 256
#define FCSRV_MAX_SRC_PREFIX 256

#define FC_MSG_VERSION 1
#define FC_MSG_BM_VERSION 1

#define FC_SKI_LENGTH 20
#define FC_MAX_SIZE 256
#define FC_IF_MAX_SIZE 32

#define FC_BM_FLAGS_UPDATE 0x00
#define FC_BM_FLAGS_WITHDRAW 0x40
#define FC_BM_FLAGS_OFFPATH 0x80
#define FC_BM_FLAGS_ONPATH 0x00

#define FC_MAX_ACL_RULE_SIZE 65535

#define FC_HDR_GENERAL_LENGTH 4
#define FC_HDR_FC_FIX_LENGTH 36
#define FC_HDR_BM_FIX_LENGTH 24
#define FC_HDR_BM_SIGLEN_POS 10

#define FC_NFT_PROG_POS "/usr/sbin/nft"

enum
{
    FC_LOG_LEVEL_EMERG = 0,
    FC_LOG_LEVEL_ERROR = 1,
    FC_LOG_LEVEL_WARNING = 2,
    FC_LOG_LEVEL_INFO = 3,
    FC_LOG_LEVEL_DEBUG = 4,
    FC_LOG_LEVEL_VERBOSE = 5,
    FC_LOG_LEVEL_N
};

enum
{
    FC_DP_MODE_LINUX,
    FC_DP_MODE_VPP,
    FC_DP_MODE_H3C,
    FC_DP_MODE_NONE,
    FC_DP_MODE_N
};

enum
{
    FC_FCS_ADDR_TYPE_DEFAULT = 0,
    FC_FCS_ADDR_TYPE_V4 = 0,
    FC_FCS_ADDR_TYPE_V6 = 1,
};

enum
{
    FC_MSG_BASE = 0,
    FC_MSG_PUBKEY = 1, // pubkey information, not implement, from RPKI.
    FC_MSG_BGPD = 2,   // broadcast message from BGP router to FCS
    FC_MSG_BC = 3,     // broadcast message from FCS to FCS
    FC_MSG_TOPO = 4,   // topo link information from BGP router to FCS
    FC_MSG_N
};

enum
{
    FC_ACT_ADD = 0, // add/update
    FC_ACT_DEL = 1, // del/withdraw
    FC_ACT_N
};

enum
{
    FC_HASH_ALGO_SHA256,
    FC_HASH_ALGO_SHA1,
    FC_HASH_ALGO_MD5,
    FC_HASH_ALGO_CRC32,
};

#define FC_ASSERT_RET_BASE(ret, msg)                  \
    do                                                \
    {                                                 \
        if (ret != 0)                                 \
        {                                             \
            DIAG_ERROR("%s:%d error: ret is not 0.  " \
                       "msg: %s\n",                   \
                       __func__, __LINE__, msg);      \
        }                                             \
    } while (0)

#define FC_ASSERT_RET(ret) FC_ASSERT_RET_BASE(ret, "")

#define FC_ASSERT_RETP(retp)                             \
    do                                                   \
    {                                                    \
        if (retp == NULL)                                \
        {                                                \
            DIAG_ERROR("%s:%d error: pointer is NULL\n", \
                       __func__, __LINE__);              \
        }                                                \
    } while (0)

#define FC_MEM_CHECK(expr)                             \
    do                                                 \
    {                                                  \
        if (!(expr))                                   \
        {                                              \
            DIAG_ERROR("[%s:%d] ERROR: memory leak\n", \
                       __func__, __LINE__);            \
        }                                              \
    } while (0)

#define FC_MEM_FREE(ptr) \
    do                   \
    {                    \
        if (ptr)         \
        {                \
            free(ptr);   \
            ptr = NULL;  \
        }                \
    } while (0)

struct prefix
{
    uint8_t family;
    uint16_t prefixlen;
    union
    {
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
    u8 ski[FC_SKI_LENGTH];
    u8 algo_id;
    u8 flags;
    u16 siglen;
    u8 sig[80]; // DER format default 64B => ~72B
} FC_t;

typedef struct FCList_s
{
    int length; // length of FCs
    int size;   // number of FC in fcs
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
    char ifname[INET6_ADDRSTRLEN];
} FC_acs_if_t;

typedef struct FC_acs_s
{
    int ipv4_num;
    int ipv6_num;
    FC_acs_if_t ipv4[FC_IF_MAX_SIZE];
    FC_acs_if_t ipv6[FC_IF_MAX_SIZE];
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

typedef struct FC_node_linkinfo_s
{
    int fd;
    int family; // AF_INET, AF_INET6
    struct sockaddr sockaddr;
    int infotype; // 1 for fcs/bm, 2 for aer/bgpd
    void *infodata;
} FC_node_linkinfo_t;

typedef struct FC_ht_node_linkinfo_s
{
    htbl_node_t hnode; // htbl node must be the first one
    int fd;
    int family; // AF_INET, AF_INET6
    struct sockaddr sockaddr;
    int infotype; // 1 for fcs/bm, 2 for aer/bgpd
    void *infodata;
} FC_ht_node_linkinfo_t;

/* ds-binding-message */
typedef struct FC_msg_hdr_st
{
    u8 version; // current is 1
    u8 type;    // 1 for pubkey, 2 for bm_bgpd, 3 for bm_broadcast
    u16 length;
} FC_msg_hdr_t;

typedef struct FC_msg_bm_st
{
    u8 bmversion;   // FC_MSG_BM_VERSION
    u8 ipversion;   // 4 for ipv4, 6 for ipv6
    u8 flags;       // 1st bit, 0x00 for onpath nodes, 0x80 for offpath,
                    // 2nd bit, 0x00 for add/update, 0x40 for del/withdraw
    u8 algoid;      // 0 for add/update, 1 for del/withdraw
    u16 src_ip_num; // src ip prefix num, boundary
    u16 dst_ip_num; // dst ip prefix num, boundary
    u16 fc_num;     // num of fc in fclist, boundary
    u16 siglen;
    u32 local_asn; // local as number
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

typedef struct ht_acl_rule_info_st
{
    u32 acl_rule_info_key;
    u8 ipversion;
    char saddr[INET6_ADDRSTRLEN];
    u8 sprefixlen;
    char daddr[INET6_ADDRSTRLEN];
    u8 dprefixlen;
    u32 acl_group_index;
    u16 rule_id;
    u8 direction;
    UT_hash_handle hh; /* makes this structure hashable */
} ht_acl_rule_info_t;

typedef struct ht_acl_group_info_st
{
    u32 iface_index;
    u32 acl_group_index;
    u32 acl_rule_in_id;
    u32 acl_rule_out_id;
    ht_acl_rule_info_t *ht_acl_rule_info;
    UT_hash_handle hh;
} ht_acl_group_info_t;

typedef struct FC_router_iface_info_st
{
    struct FC_router_iface_info_st *next;
    u32 iface_index;
} FC_router_iface_info_t;

typedef struct FC_router_link_info_st
{
    struct FC_router_link_info_st *next;
    u32 neighbor_asn;
    FC_router_iface_info_t *iface_list;
} FC_router_link_info_t;

typedef struct FC_router_info_st
{
    int fd; // router bgp fd, will remove this data-structue when closed
    struct FC_router_info_st *next;
    u32 bgpid;
    char host[INET6_ADDRSTRLEN];
    u16 port;
    char username[FC_MAX_SIZE];
    char password[FC_MAX_SIZE];
    u32 acl_group_index;
    py_config_t py_config;
    FC_router_link_info_t *links;
} FC_router_info_t;

typedef struct FC_server_s
{
    char *prog_name;
    char *prog_addr4;
    char *prog_addr6;
    u8 log_level;
    bool clear_fc_db;
    int use_data_plane;
    u32 local_asn;

    char hash_algorithm[64];
    int hash_algorithm_id;

    u8 asns_num; /* as-ip totoal num, of course it's number of AS */
    u32 asns[FCSRV_MAX_LINK_AS];
    sqlite3 *db;
    htbl_ctx_t ht_as;
    htbl_ctx_t ht_prefix;

    int sockfd;
    int listen_port;
    int epollfd;

    int routers_num;
    FC_router_info_t *routers;
    ht_acl_group_info_t *ht_acl_group_info;

    int fcs_addr_type;
    char *fc_db_fname;
    char *config_fname;
    char *prikey_fname;
    char *certs_location;
    FC_node_as_t aps[FCSRV_MAX_LINK_AS];
    EC_KEY *pubkey;
    EC_KEY *prikey;
    u8 ski[FC_SKI_LENGTH];
    int nics_num;
    char nics[FC_MAX_SIZE][20]; /* network interface cards */
} FC_server_t;

extern FC_server_t g_fc_server;

#endif // DEFINES_H
