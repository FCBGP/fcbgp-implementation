/********************************************************************************
* File Name:    utils.h
* Author:       basilguo@163.com
* Created Time: 2023-09-27 08:13:56
* Description:
********************************************************************************/

#ifndef UTILS_H
#define UTILS_H

#include <arpa/inet.h>
#include "common.h"

#define FCSRV_MAX_LINK_AS 256
#define FCSRV_MAX_SRC_PREFIX 256

typedef struct acs_s
{
    char ipv4[INET_ADDRSTRLEN];
    char ipv6[INET6_ADDRSTRLEN];
} acs_t;

typedef struct ip_s
{
    struct sockaddr ip;
    u8 prefix_length;
} ip_t;

typedef struct prefix_s
{
    ip_t ipv4[FCSRV_MAX_SRC_PREFIX];
    ip_t ipv6[FCSRV_MAX_SRC_PREFIX];
} prefix_t;

typedef struct asn_ip_s
{
    acs_t acs;
    prefix_t prefix;
} asn_ip_t;

typedef struct node_as_s
{
    u32 asn;
    asn_ip_t ap;
} node_as_t;

typedef struct fcserver_s
{
    u8 aps_num;
    u32 local_asn;
    node_as_t aps[FCSRV_MAX_LINK_AS];
} fcserver_t;

#endif // UTILS_H
