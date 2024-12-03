#ifndef LIBPHDR_H
#define LIBPHDR_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libchecksum.h"
#include "libendian.h"

/* ethernet protocol */
#define PHDR_ETH_P_LOOP 0x0060
#define PHDR_ETH_P_PUP 0x0200
#define PHDR_ETH_P_PUPAT 0x0201
#define PHDR_ETH_P_IP 0x0800
#define PHDR_ETH_P_X25 0x0805
#define PHDR_ETH_P_BPQ 0x08FF
#define PHDR_ETH_P_IEEEPUP 0x0a00
#define PHDR_ETH_P_IEEEPUPAT 0x0a01
#define PHDR_ETH_P_DEC 0x6000
#define PHDR_ETH_P_DNA_DL 0x6001
#define PHDR_ETH_P_DNA_RC 0x6002
#define PHDR_ETH_P_DNA_RT 0x6003
#define PHDR_ETH_P_LAT 0x6004
#define PHDR_ETH_P_DIAG 0x6005
#define PHDR_ETH_P_CUST 0x6006
#define PHDR_ETH_P_SCA 0x6007
#define PHDR_ETH_P_ATALK 0x809B
#define PHDR_ETH_P_AARP 0x80F3
#define PHDR_ETH_P_8021Q 0x8100
#define PHDR_ETH_P_IPX 0x8137
#define PHDR_ETH_P_PPP_SES 0x8864
#define PHDR_ETH_P_ATMMPOA 0x884c
#define PHDR_ETH_P_ATMFATE 0x8884

#define PHDR_ETH_P_IPV4 0x0800
#define PHDR_ETH_P_IPV6 0x86DD
#define PHDR_ETH_P_ARP 0x0806
#define PHDR_ETH_P_RARP 0x8035
#define PHDR_ETH_P_TRUNK 0x8100

#define PHDR_ETH_P_PPP_DISC 0x8863
#define PHDR_ETH_P_PPP_SESS 0x8864

#define PHDR_ETH_P_COMM 0x0706

/* ip protocol */
#define PHDR_IP_P_IP 0
#define PHDR_IP_P_EGP 8
#define PHDR_IP_P_PUP 12
#define PHDR_IP_P_IDP 22
#define PHDR_IP_P_IPV6 41
#define PHDR_IP_P_ESP 50
#define PHDR_IP_P_AH 51
#define PHDR_IP_P_COMP 108
#define PHDR_IP_P_MAX 256

#define PHDR_IP_P_ICMP 1
#define PHDR_IP_P_IGMP 2
#define PHDR_IP_P_IPIP 4
#define PHDR_IP_P_TCP 6
#define PHDR_IP_P_UDP 17
#define PHDR_IP_P_RSVP 46
#define PHDR_IP_P_GRE 47
#define PHDR_IP_P_PIM 103
#define PHDR_IP_P_VRRP 112
#define PHDR_IP_P_RAW 255
#define PHDR_IP_P_EIP 254

/* ipv4 icmp type */
#define PHDR_IP4_ICMP_ECHOREPLY 0       /* Echo Reply */
#define PHDR_IP4_ICMP_DEST_UNREACH 3    /* Destination Unreachable */
#define PHDR_IP4_ICMP_SOURCE_QUENCH 4   /* Source Quench */
#define PHDR_IP4_ICMP_REDIRECT 5        /* Redirect (change route) */
#define PHDR_IP4_ICMP_ECHO 8            /* Echo Request */
#define PHDR_IP4_ICMP_ROUTE_ADV 9       /* route advertisement */
#define PHDR_IP4_ICMP_ROUTE_SOLICIT 10  /* route solicit */
#define PHDR_IP4_ICMP_TIME_EXCEEDED 11  /* Time Exceeded */
#define PHDR_IP4_ICMP_PARAMETERPROB 12  /* Parameter Problem */
#define PHDR_IP4_ICMP_TIMESTAMP 13      /* Timestamp Request */
#define PHDR_IP4_ICMP_TIMESTAMPREPLY 14 /* Timestamp Reply */
#define PHDR_IP4_ICMP_INFO_REQUEST 15   /* Information Request */
#define PHDR_IP4_ICMP_INFO_REPLY 16     /* Information Reply */
#define PHDR_IP4_ICMP_ADDRESS 17        /* Address Mask Request */
#define PHDR_IP4_ICMP_ADDRESSREPLY 18   /* Address Mask Reply */

/* ipv4, icmp Codes for UNREACH. */
#define PHDR_IP4_ICMP_NET_UNREACH 0  /* Network Unreachable */
#define PHDR_IP4_ICMP_HOST_UNREACH 1 /* Host Unreachable */
#define PHDR_IP4_ICMP_PROT_UNREACH 2 /* Protocol Unreachable */
#define PHDR_IP4_ICMP_PORT_UNREACH 3 /* Port Unreachable */
#define PHDR_IP4_ICMP_FRAG_NEEDED 4  /* Fragmentation Needed/DF set */
#define PHDR_IP4_ICMP_SR_FAILED 5    /* Source Route failed */
#define PHDR_IP4_ICMP_NET_UNKNOWN 6
#define PHDR_IP4_ICMP_HOST_UNKNOWN 7
#define PHDR_IP4_ICMP_HOST_ISOLATED 8
#define PHDR_IP4_ICMP_NET_ANO 9
#define PHDR_IP4_ICMP_HOST_ANO 10
#define PHDR_IP4_ICMP_NET_UNR_TOS 11
#define PHDR_IP4_ICMP_HOST_UNR_TOS 12
#define PHDR_IP4_ICMP_PKT_FILTERED 13   /* Packet filtered */
#define PHDR_IP4_ICMP_PREC_VIOLATION 14 /* Precedence violation */
#define PHDR_IP4_ICMP_PREC_CUTOFF 15    /* Precedence cut off */

/* ipv4, icmp, Codes for REDIRECT. */
#define PHDR_IP4_ICMP_REDIR_NET 0     /* Redirect Net */
#define PHDR_IP4_ICMP_REDIR_HOST 1    /* Redirect Host */
#define PHDR_IP4_ICMP_REDIR_NETTOS 2  /* Redirect Net for TOS */
#define PHDR_IP4_ICMP_REDIR_HOSTTOS 3 /* Redirect Host for TOS */

/* Codes for TIME_EXCEEDED. */
#define PHDR_IP4_ICMP_EXC_TTL 0      /* TTL count exceeded */
#define PHDR_IP4_ICMP_EXC_FRAGTIME 1 /* Frag Reass time exceeded */

#define PHDR_TCP_FLAG_SYN 0x02
#define PHDR_TCP_FLAG_FIN 0x01
#define PHDR_TCP_FLAG_RST 0x04
#define PHDR_TCP_FLAG_PSH 0x08
#define PHDR_TCP_FLAG_ACK 0x10
#define PHDR_TCP_FLAG_URG 0x20

#define PHDR_UDP_IKE_PORT0 500
#define PHDR_UDP_IKE_PORT1 4500

#define PHDR_TCP_L2TP_PORT 1720
#define PHDR_UDP_L2TP_PORT 1701

#define ETH_ALEN 6
#define ETH_HLEN 14
#define ETH_DATA_LEN 1500  /* Max. octets in payload */
#define ETH_FRAME_LEN 1514 /* Max. octets in frame sans FCS */
#define ETH_ADDR_FMT "%02x:%02x:%02x:%02x:%02x:%02x"
#define ETH_ADDR_PRINT(mac)                                                    \
    (mac)[0], (mac)[1], (mac)[2], (mac)[3], (mac)[4], (mac)[5]

typedef struct phdr_ether_st
{
    uint8_t dst_mac[6];
    uint8_t src_mac[6];
    uint16_t protocol;
} __attribute__((packed)) phdr_ether_t;

typedef struct phdr_trunk_st
{
    uint8_t dst_mac[6];
    uint8_t src_mac[6];
    uint16_t protocol;
    uint16_t vlan;
    uint16_t second_protocol;
} __attribute__((packed)) phdr_trunk_t;

#define PHDR_IP_DF 0x4000     /* Flag: "Don't Fragment" */
#define PHDR_IP_MF 0x2000     /* Flag: "More Fragments" */
#define PHDR_IP_OFFSET 0x1FFF /* "Fragment Offset" part */

#define PHDR_IPV4_PROTOCOL(ipv4) (ipv4->protocol)
#define PHDR_IPV4_TOTLEN(ipv4) (endian_ntohs(ipv4->total_len))
#define PHDR_IPV4_HDRLEN(ipv4) (ipv4->ihl * 4)
#define PHDR_IPV4_IS_FRAG(ipv4)                                                \
    (ipv4->frag_offset & endian_htons(PHDR_IP_MF | PHDR_IP_OFFSET))

typedef struct phdr_ipv4_st
{
#if defined(ARCH_IS_LITTLE_ENDIAN)
    uint8_t ihl : 4, version : 4;
#else
    uint8_t version : 4, ihl : 4;
#endif

    uint8_t tos;
    uint16_t total_len;
    uint16_t ident;
    uint16_t frag_offset;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t chksum;
    uint32_t src_addr;
    uint32_t dst_addr;
} __attribute__((packed)) phdr_ipv4_t;

#define IPADDR4_FMT "%u.%u.%u.%u"
#define IPADDR4_HPRINT(hip)                                                    \
    ((hip)&0xFF000000) >> 24, ((hip)&0x00FF0000) >> 16,                        \
        ((hip)&0x0000FF00) >> 8, (hip)&0x000000FF
#define IPADDR4_NPRINT(nip)                                                    \
    (nip) & 0x000000FF, ((nip)&0x0000FF00) >> 8, ((nip)&0x00FF0000) >> 16,     \
        ((nip)&0xFF000000) >> 24

/*
 * ipaddr4 is in host byte order
 */
static inline int ipaddr4_is_loopback(uint32_t ipaddr4)
{
    return ((ipaddr4 & 0xFF000000) == 0x7F000000);
}

static inline int ipaddr4_is_multicast(uint32_t ipaddr4)
{
    return ((ipaddr4 & 0xF0000000) == 0xE0000000);
}

static inline int ipaddr4_is_broadcast(uint32_t ipaddr4)
{
    return (ipaddr4 == 0xFFFFFFFF);
}

static inline int ipaddr4_is_netmask(uint32_t ipaddr4)
{
    if (ipaddr4 == 0)
    {
        return 0;
    }

    while (ipaddr4)
    {
        if ((ipaddr4 & 0x80000000) == 0)
        {
            return 0;
        }

        ipaddr4 = ipaddr4 << 1;
    }

    return 1;
}

static inline int ipaddr4_masklen(uint32_t mask)
{
    int i;

    for (i = 31; i >= 0; i--)
    {
        if ((mask & (1 << i)) == 0)
        {
            return 31 - i;
        }
    }

    return 32;
}

static inline int ipaddr4_is_innet(uint32_t ipaddr4, uint32_t net,
                                   uint32_t mask)
{
    if (ipaddr4 == (ipaddr4 & mask))
    {
        return 0;
    }

    if (ipaddr4 == (ipaddr4 | (~mask)))
    {
        return 0;
    }

    if ((ipaddr4 & mask) == (net & mask))
    {
        return 1;
    }

    return 0;
}

static inline int ipaddr4_is_samenet(uint32_t net1, uint32_t mask1,
                                     uint32_t net2, uint32_t mask2)
{
    if (mask1 != mask2)
    {
        return 0;
    }

    if ((net1 & mask1) != (net2 & mask2))
    {
        return 0;
    }

    return 1;
}

#define PHDR_TCPV4_HDRLEN(tcpv4) (tcpv4->doff * 4)
typedef struct phdr_tcpv4_st
{
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;
    uint32_t ack_seq;
#if defined(ARCH_IS_LITTLE_ENDIAN)
    uint16_t res1 : 4, doff : 4, fin : 1, syn : 1, rst : 1, psh : 1, ack : 1,
        urg : 1, ece : 1, cwr : 1;
#else
    uint16_t doff : 4, res1 : 4, cwr : 1, ece : 1, urg : 1, ack : 1, psh : 1,
        rst : 1, syn : 1, fin : 1;
#endif
    uint16_t window;
    uint16_t chksum;
    uint16_t urgptr;
} __attribute__((packed)) phdr_tcpv4_t;

/*
 * The following before/after/between routines deal with comparing 32 bit
 * unsigned ints and worry about wraparound (automatic with unsigned
 * arithmetic).
 */
static inline int before(uint32_t seq1, uint32_t seq2)
{
    return (int32_t)(seq1 - seq2) < 0;
}

#define after(seq2, seq1) before(seq1, seq2)

/* is s2<=s1<=s3 ? */
static inline int between(uint32_t seq1, uint32_t seq2, uint32_t seq3)
{
    return (seq3 - seq2) >= (seq1 - seq2);
}

typedef struct phdr_udpv4_st
{
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t size;
    uint16_t chksum;
} __attribute__((packed)) phdr_udpv4_t;

#define PHDR_ICMP_TYPE(icmp) (icmp->type)
#define PHDR_ICMP_ID(icmp) (icmp->echo.id)
#define PHDR_ICMP_CODE(icmp) (icmp->code)

typedef struct phdr_icmpv4_st
{
    uint8_t type;
    uint8_t code;
    uint16_t chksum;
    union
    {
        struct
        {
            uint16_t id;
            uint16_t sequence;
        } echo;
        struct
        {
            uint16_t __unused;
            uint16_t mtu;
        } frag;
        uint32_t gateway;
    };
} __attribute__((packed)) phdr_icmpv4_t;

static inline int phdr_icmp_type_is_error(uint8_t type)
{
    switch (type)
    {
        case PHDR_IP4_ICMP_DEST_UNREACH:
        case PHDR_IP4_ICMP_SOURCE_QUENCH:
        case PHDR_IP4_ICMP_REDIRECT:
        case PHDR_IP4_ICMP_TIME_EXCEEDED:
        case PHDR_IP4_ICMP_PARAMETERPROB:
            return 1;
        default:
            return 0;
    }
}

static inline int phdr_icmp_type_is_request(uint8_t type)
{
    switch (type)
    {
        case PHDR_IP4_ICMP_ECHO:
        case PHDR_IP4_ICMP_ROUTE_ADV:
        case PHDR_IP4_ICMP_TIMESTAMP:
        case PHDR_IP4_ICMP_INFO_REQUEST:
        case PHDR_IP4_ICMP_ADDRESS:
            return 1;
        default:
            return 0;
    }
}

static inline uint8_t phdr_icmp_get_request_type(uint8_t reply_type)
{
    switch (reply_type)
    {
        case PHDR_IP4_ICMP_ECHOREPLY:
            return PHDR_IP4_ICMP_ECHO;
        case PHDR_IP4_ICMP_ROUTE_SOLICIT:
            return PHDR_IP4_ICMP_ROUTE_ADV;
        case PHDR_IP4_ICMP_TIMESTAMPREPLY:
            return PHDR_IP4_ICMP_TIMESTAMP;
        case PHDR_IP4_ICMP_INFO_REPLY:
            return PHDR_IP4_ICMP_INFO_REQUEST;
        case PHDR_IP4_ICMP_ADDRESSREPLY:
            return PHDR_IP4_ICMP_ADDRESS;
        default:
            return 0;
    };
}

typedef struct phdr_arpv4_st
{
    uint16_t hard_type;
    uint16_t protocol;
    uint8_t hard_addr_size;
    uint8_t prot_addr_size;
    uint16_t opcode;
    uint8_t sender_mac[6];
    uint32_t sender_ip;
    uint8_t target_mac[6];
    uint32_t target_ip;
} __attribute__((packed)) phdr_arpv4_t;

static inline uint16_t phdr_ip_fast_csum(phdr_ipv4_t* iphdr)
{
    iphdr->chksum = 0;
    iphdr->chksum = ip_fast_csum(iphdr, iphdr->ihl);

    return iphdr->chksum;
}

static inline uint16_t phdr_tcp_fast_csum(phdr_ipv4_t* iphdr,
                                          phdr_tcpv4_t* tcphdr, int tcplen)
{
    uint32_t pseudo_csum = csum_tcpudp_nofold(iphdr->src_addr, iphdr->dst_addr,
                                              tcplen, iphdr->protocol, 0);

    tcphdr->chksum = 0;
    tcphdr->chksum = csum_fold(csum_partial(tcphdr, tcplen, pseudo_csum));

    return tcphdr->chksum;
}

#endif
