/******************************************************
 * File Name:    bgp_fc.h
 * Author:       basilguo@163.com
 * Created Time: 2023-09-19 02:21:30
 * Description:
 ******************************************************/
#ifndef BGP_FC_H
#define BGP_FC_H

#include "lib/hash.h"
#include "lib/jhash.h"
#include "lib/linklist.h"
#include "lib/prefix.h"
#include "lib/zlog.h"

#include "bgpd/bgpd.h"

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

#include <json-c/json.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/pem.h>

/*
*/

#include <openssl/x509.h>
#include <openssl/x509v3.h>


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
#define FC_BM_VERSION                   1
#define FC_BUFF_SIZE                    1000007
#define FCSRV_HTBL_BUCKETS_SIZE         1000007
#define FCSRV_MAX_LINK_AS               256
#define FCSRV_MAX_SRC_PREFIX            256

#define FC_SKI_LENGTH                   20
// sizeof(u32)*3+FC_SKI_LENGTH+sizeof(u8)*2+sizeof(u16)
#define FC_FIX_LENGTH                   36
#define FC_MAX_SIZE                     256

#define FC_HDR_GENERAL_LENGTH           4

#define FC_MSG_SKI                      1
#define FC_MSG_BGPD                     2
#define FC_MSG_BC                       3

#define FC_NODE_TYPE_ONPATH             0x00
#define FC_NODE_TYPE_OFFPATH            0x80

#define FC_ACTION_ADD_UPDATE            0x00
#define FC_ACTION_DEL_WITHDRAW          0x40

#define FC_ALGO_ID                      0x01

#define FC_CONFIG_FILE "/etc/frr/assets/config.json"

#define FC_ASSERT_RET(ret)                                  \
    do {                                                    \
        if (ret != 0) {                                     \
            fprintf(stderr, "%s:%d error: ret is not 0\n",  \
                    __func__, __LINE__);                    \
            exit(-1);                                       \
        }                                                   \
    } while (0)                                             \

#define FC_ASSERT_RETP(retp)                                    \
    do {                                                        \
        if (pret == 0) {                                        \
            fprintf(stderr, "%s:%d error: pointer is NULL\n",   \
                    __func__, __LINE__);                        \
            exit(-1);                                           \
        }                                                       \
    } while (0)

enum
{
    FC_HASH_ALGO_UNKNOWN,
    FC_HASH_ALGO_SHA256,
    FC_HASH_ALGO_SHA1,
    FC_HASH_ALGO_MD5,
    FC_HASH_ALGO_CRC32,
};

typedef struct SKI_ECKEY_s
{
    u32 asn;
    u8 ski[FC_SKI_LENGTH];
    EC_KEY *pubkey;
} SKI_ECKEY_t;

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
    int size; // number of FC in fcs
    int length; // total length of fcs
    struct prefix ipprefix;
    struct list *fcs;
} FCList_t;

typedef struct FC_ht_node_asprefix_s
{
    u32 asn;
    struct hash *htbl;  // prefix hashtable
} FC_ht_node_asprefix_t;

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

// for hashtable node
typedef struct FC_ht_node_as_s
{
    // htbl_node_t hnode; // htbl node must be the first one
    u32 asn;
    FC_asn_ip_t ap;
} FC_ht_node_as_t;

/* ds-binding-message */
typedef struct FC_msg_hdr_st
{
    u8 version; // current is 1
    u8 type;    // 1 for pubkey, 2 for bm
    u16 length;
} FC_msg_hdr_t;

typedef struct FC_msg_bm_st
{
    u8 bmversion;
    u8 ipversion;  // 4 for ipv4, 6 for ipv6
    u8 flags;       // 1st bit, 0x00 for onpath nodes, 0x80 for offpath,
                    // 2nd bit, 0x00 for add/update, 0x40 for del/withdraw
    u8 algoid;     // 0 for add/update, 1 for del/withdraw
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

typedef struct FC_config_s
{
    int fc_listen_port;
    EC_KEY *prikey;
    EC_KEY *pubkey;
    uint8_t ski[20];
    int hash_algorithm_id;
    /* store the pubkey of each as */
    struct hash *fc_ht_ski_ecpubkey;
    /* store the update NLRI info of each as-path */
    struct hash *fc_ht_asprefix;
} FC_config_t;

extern FC_config_t fc_config;

/* SIG */
extern int fc_read_eckey_from_file(int is_pub_key, EC_KEY **pkey);
extern int fc_read_eckey_from_filepath(const char *file,
        int is_pub_key, EC_KEY **pkey);
extern int fc_get_ecpubkey_and_ski(u32 asn, const char *fpath,
        EC_KEY **ecpubkey, u8 *ecski);
extern int fc_base64_encode(const unsigned char *msg,
        size_t length, char * b64msg);
extern int fc_base64_decode(const char *b64msg, unsigned char **msg,
        size_t *length);
extern int fc_ecdsa_sign(EC_KEY *prikey, const char *const msg, int msglen,
        unsigned char **sigbuff, unsigned int *siglen);
extern int fc_ecdsa_verify(EC_KEY *pubkey, const char *const msg, int msglen,
        const unsigned char *sigbuff, unsigned int siglen);

/* HASHTABLE */
extern unsigned int fc_ht_asprefix_hash_key(const void *data);
extern bool fc_ht_asprefix_hash_cmp(const void *a, const void *b);
extern unsigned int fc_ht_prefix_hash_key(const void *data);
extern bool fc_ht_prefix_hash_cmp(const void *a, const void *b);
extern unsigned int fc_ht_as_hash_key(const void *data);
extern bool fc_ht_as_hash_cmp(const void *a, const void *b);
extern unsigned int fc_ht_ski_eckey_hash_key(const void *data);
extern bool fc_ht_ski_eckey_hash_cmp(const void *a, const void *b);

/* SERVER */
#define FC_CFG_DEFAULT_LISTEN_PORT 23160
#define FC_CFG_DEFAULT_HASH_ALGO "SHA256"
extern int fc_send_packet_to_fcserver(u8 ipversion, char *buff, int bufflen);

extern int bgp_fc_init(struct bgp_master *bm);
extern int bgp_fc_destroy(struct bgp_master *bm);

/* UTILS */
extern void fc_print_bin(const char *msg, void *data, int len);

#endif // BGP_FC_H
