/********************************************************************************
* File Name:    ds_asn_ip.h
* Author:       basilguo@163.com
* Created Time: 2023-09-27 08:13:56
* Description:
********************************************************************************/

#ifndef DS_ASN_IP_H
#define DS_ASN_IP_H

#include <arpa/inet.h>
#include "common.h"
#include "libhtable.h"

typedef struct acs_s
{
    char ipv4[INET_ADDRSTRLEN];
    char ipv6[INET6_ADDRSTRLEN];
} acs_t;

typedef struct ip_s
{
    // struct sockaddr ip;
    struct sockaddr ip;
    u8 prefix_length;
} ip_t;

typedef struct prefix_s
{
    int ip4s_num;
    int ip6s_num;
    ip_t ip4s[FCSRV_MAX_SRC_PREFIX];
    ip_t ip6s[FCSRV_MAX_SRC_PREFIX];
} prefix_t;

typedef struct asn_ip_s
{
    acs_t acs;
    prefix_t prefix;
} asn_ip_t;

// for hashtable meta
typedef struct node_as_s
{
    u32 asn;
    asn_ip_t ap;
} node_as_t;

// for hashtable node
typedef struct ht_node_as_s
{
    htbl_node_t hnode; // htbl node must be the first one
    u32 asn;
    asn_ip_t ap;
} ht_node_as_t;

#endif // DS_ASN_IP_H
