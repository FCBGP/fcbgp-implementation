#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>           // close()
#include <string.h>           // strcpy, memset(), and memcpy()

#include <netdb.h>            // struct addrinfo
#include <sys/types.h>        // needed for socket(), uint8_t, uint16_t
#include <sys/socket.h>       // needed for socket()
#include <netinet/in.h>       // IPPROTO_UDP, INET6_ADDRSTRLEN
#include <netinet/ip.h>       // IP_MAXPACKET (which is 65535)
#include <netinet/ip6.h>      // struct ip6_hdr
#include <netinet/udp.h>      // struct udphdr
#include <arpa/inet.h>        // inet_pton() and inet_ntop()
#include <sys/ioctl.h>        // macro ioctl is defined
#include <bits/ioctls.h>      // defines values for argument "request" of ioctl.
#include <net/if.h>           // struct ifreq
#include <linux/if_ether.h>   // ETH_P_IP = 0x0800, ETH_P_IPV6 = 0x86DD
#include <linux/if_packet.h>  // struct sockaddr_ll (see man 7 packet)
#include <net/ethernet.h>
#include <ifaddrs.h>

#include <errno.h>            // errno, perror()

#include "libdiag.h"
#include "libnio.h"
#include "libdhcpv6.h"
#include "hex.h"

// Define some constants.
#define ETH_HDRLEN 14  // Ethernet header length
#define IP6_HDRLEN 40  // IPv6 header length
#define UDP_HDRLEN  8  // UDP header length, excludes data

extern uint8_t g_scanner_sip6[64];
extern uint8_t g_scanner_dip6[64];

int getmac(char *ifname, char *mac){
    struct ifreq ifr;
    int sockfd;

    memset(&ifr, 0, sizeof(ifr));
    strcpy(ifr.ifr_ifrn.ifrn_name, ifname);
    ifr.ifr_ifrn.ifrn_name[strlen(ifname)] = '\0';
    sockfd=socket(AF_INET6, SOCK_DGRAM,0);
    if(sockfd == -1){
        perror("socket");
    }
    if(ioctl(sockfd, SIOCGIFHWADDR, &ifr) != 0){
        perror("ioctl");
        close(sockfd);
        return -1;
    }
    close(sockfd);
    memcpy(mac, ifr.ifr_ifru.ifru_hwaddr.sa_data, 6);
    return 0;
}

int get_ipv6_by_ifname(char *ifname, char *ipv6)
{
    struct ifaddrs *ifaddr, *ifa;
    int family, s;

    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        exit(EXIT_FAILURE);
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL)
            continue;

        if (strcmp(ifa->ifa_name, ifname) !=0 )
            continue;
        family = ifa->ifa_addr->sa_family;

        if (family == AF_INET6) {
            s = getnameinfo(ifa->ifa_addr,
                    sizeof(struct sockaddr_in6),
                    ipv6, 32,
                    NULL, 0, NI_NUMERICHOST);
            if (s != 0) {
                printf("getnameinfo() failed: %s\n", gai_strerror(s));
                return -1;
            }
            break;
        }
    }

    freeifaddrs(ifaddr);
    return 0;
}

int pkt6_eth(char *ifname, char *smac, char *dmac, uint16_t proto, uint8_t *data_ii)
{
    if (data_ii == NULL) {
        DIAG_ERROR("data_ii must not be NULL.\n");
        return -1;
    }

    char smac_hex[8] = {0};
    char dmac_hex[8] = {0};
    if((smac == NULL) || *smac == 0) {
        getmac(ifname, smac_hex);
    } else {
        str2hex(smac, smac_hex);
    }
    str2hex(dmac, dmac_hex);

    // Destination and Source MAC addresses
    memcpy(data_ii, dmac_hex, 6);
    memcpy(data_ii + 6, smac_hex, 6);

    data_ii[12] = proto >> 8;
    data_ii[13] = proto & 0xff;

    return 0;
}

int pkt6_ip(char *ifname, char *sip, char *dip, short proto, char hlim, int tc, char *data_iii, int payload_len)
{
    int ret;
    struct ip6_hdr *iphdr = (struct ip6_hdr *)data_iii;

    if (data_iii == NULL) {
        DIAG_ERROR("data_iii must not be NULL.\n");
        return -1;
    }

    // IPv6 header

    // IPv6 version (4 bits), Traffic class (8 bits), Flow label (20 bits)
    iphdr->ip6_flow = htonl ((6 << 28) | ((tc%256) << 20) | 0);

    // Payload length (16 bits): UDP header + UDP data
    iphdr->ip6_plen = htons(UDP_HDRLEN + payload_len);

    // Next header (8 bits): 17 for UDP
    iphdr->ip6_nxt = proto;

    // Hop limit (8 bits): default to maximum value
    iphdr->ip6_hops = hlim;

//  do at my_sender.c
//   char sip6[64] = {0};
//   if((sip == NULL) || (*sip=='\0')) {
//       get_ipv6_by_ifname(ifname, sip6);
//       sip = sip6;
//   }
//   strncpy(g_scanner_sip6, sip6, sizeof(g_scanner_sip6));

    // Source IPv6 address (128 bits)
    if ((ret = inet_pton (AF_INET6, sip, &(iphdr->ip6_src))) != 1) {
        DIAG_ERROR("inet_pton() failed.\nError message: %d", ret);
        return -1;
    }

    char dip6[64] = {0};
    if((dip == NULL) || (*dip=='\0')) {
        strcpy(dip6, "ff02::1");
        dip = dip6;
    }
    strncpy(g_scanner_dip6, dip6, sizeof(g_scanner_dip6));

    // Destination IPv6 address (128 bits)
    if ((ret = inet_pton (AF_INET6, dip, &(iphdr->ip6_dst))) != 1) {
        DIAG_ERROR("inet_pton() failed.\nError message: %d", ret);
        return -1;
    }

    return 0;
}

// Computing the internet checksum (RFC 1071).
// Note that the internet checksum does not preclude collisions.
uint16_t checksum (uint16_t *addr, int len)
{
    int count = len;
    register uint32_t sum = 0;
    uint16_t answer = 0;

    // Sum up 2-byte values until none or only one byte left.
    while (count > 1) {
        sum += *(addr++);
        count -= 2;
    }

    // Add left-over byte, if any.
    if (count > 0) {
        sum += *(uint8_t *) addr;
    }

    // Fold 32-bit sum into 16 bits; we lose information by doing this,
    // increasing the chances of a collision.
    // sum = (lower 16 bits) + (upper 16 bits shifted right 16 bits)
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    // Checksum is one's compliment of sum.
    answer = ~sum;

    return (answer);
}

// Build IPv6 UDP pseudo-header and call checksum function (Section 8.1 of RFC 2460).
uint16_t udp6_checksum (struct ip6_hdr iphdr, struct udphdr udphdr, uint8_t *payload, int payloadlen)
{
    char buf[IP_MAXPACKET];
    char *ptr;
    int chksumlen = 0;
    int i;

    ptr = &buf[0];  // ptr points to beginning of buffer buf

    // Copy source IP address into buf (128 bits)
    memcpy (ptr, &iphdr.ip6_src.s6_addr, sizeof (iphdr.ip6_src.s6_addr));
    ptr += sizeof (iphdr.ip6_src.s6_addr);
    chksumlen += sizeof (iphdr.ip6_src.s6_addr);

    // Copy destination IP address into buf (128 bits)
    memcpy (ptr, &iphdr.ip6_dst.s6_addr, sizeof (iphdr.ip6_dst.s6_addr));
    ptr += sizeof (iphdr.ip6_dst.s6_addr);
    chksumlen += sizeof (iphdr.ip6_dst.s6_addr);

    // Copy UDP length into buf (32 bits)
    memcpy (ptr, &udphdr.len, sizeof (udphdr.len));
    ptr += sizeof (udphdr.len);
    chksumlen += sizeof (udphdr.len);

    // Copy zero field to buf (24 bits)
    *ptr = 0; ptr++;
    *ptr = 0; ptr++;
    *ptr = 0; ptr++;
    chksumlen += 3;

    // Copy next header field to buf (8 bits)
    memcpy (ptr, &iphdr.ip6_nxt, sizeof (iphdr.ip6_nxt));
    ptr += sizeof (iphdr.ip6_nxt);
    chksumlen += sizeof (iphdr.ip6_nxt);

    // Copy UDP source port to buf (16 bits)
    memcpy (ptr, &udphdr.source, sizeof (udphdr.source));
    ptr += sizeof (udphdr.source);
    chksumlen += sizeof (udphdr.source);

    // Copy UDP destination port to buf (16 bits)
    memcpy (ptr, &udphdr.dest, sizeof (udphdr.dest));
    ptr += sizeof (udphdr.dest);
    chksumlen += sizeof (udphdr.dest);

    // Copy UDP length again to buf (16 bits)
    memcpy (ptr, &udphdr.len, sizeof (udphdr.len));
    ptr += sizeof (udphdr.len);
    chksumlen += sizeof (udphdr.len);

    // Copy UDP checksum to buf (16 bits)
    // Zero, since we don't know it yet
    *ptr = 0; ptr++;
    *ptr = 0; ptr++;
    chksumlen += 2;

    // Copy payload to buf
    memcpy (ptr, payload, payloadlen * sizeof (uint8_t));
    ptr += payloadlen;
    chksumlen += payloadlen;

    // Pad to the next 16-bit boundary
    for (i=0; i<payloadlen%2; i++, ptr++) {
        *ptr = 0;
        ptr++;
        chksumlen++;
    }

    return checksum ((uint16_t *) buf, chksumlen);
}

int pkt6_udp(uint16_t sport, uint16_t dport, char *data_iiii, unsigned char *payload, int payload_len, struct ip6_hdr iphdr)
{
    if (data_iiii == NULL) {
        DIAG_ERROR("data_iiii must not be NULL.\n");
        return -1;
    }

    // UDP header
    struct udphdr *udphdr = (struct udphdr *)data_iiii;

    // Source port number (16 bits): pick a number
    udphdr->source = htons (sport);

    // Destination port number (16 bits): pick a number
    udphdr->dest = htons (dport);

    // Length of UDP datagram (16 bits): UDP header + UDP data
    udphdr->len = htons(UDP_HDRLEN + payload_len);

    // UDP checksum (16 bits)
    udphdr->check = udp6_checksum(iphdr, *udphdr, payload, payload_len);

    return 0;
}

int get_opt(void *value, void *arg, int arg_len)
{
    dhcpv6_opt_t *opt = value;
    dhcpv6_opt_t *tmp = arg;
    if (opt->code == tmp->code) {
        tmp->len = opt->len;
        tmp->value = opt->value;
        return 1;
    }

    return 0;
}

/***
 *optcode: optcode
 *value: option message
 * return value: option length
 */
int get_option(slist_t *list, int optcode, char **value)
{
    dhcpv6_opt_t pkt_tmp;
    pkt_tmp.code = optcode;
    slist_foreach(list, get_opt, &pkt_tmp, sizeof(dhcpv6_opt_t));
    *value = pkt_tmp.value;
    return pkt_tmp.len;
}

void dhcp_option_fini (void *ptr)
{
    dhcpv6_opt_t *opt = ptr;
    free(opt->value);
    free(opt);
}

int parse_dhcp_relay_fini(dhcpv6_relay_t *pkt)
{
    slist_fini(pkt->opt_list, dhcp_option_fini);
    free(pkt->opt_list);
    free(pkt);
    return 0;
}

int parse_dhcp_fini(dhcpv6_t *pkt)
{
    slist_fini(pkt->opt_list, dhcp_option_fini);
    free(pkt->opt_list);
    free(pkt);
    return 0;
}

unsigned char *OptinReq(int *size){
    unsigned short option_code=htons(0x0006);
    unsigned short option_len=htons(0x0004);
    unsigned short oprq1=htons(0x0017);
    unsigned short oprq2=htons(0x0018);
    unsigned char * OptinReq=NULL;
    int len=0;

    OptinReq=(unsigned char *)malloc(8);
    memset(OptinReq, 0, 8);
    memcpy(OptinReq+len, &option_code, sizeof(option_code));
    len+=sizeof(option_code);
    memcpy(OptinReq+len, &option_len, sizeof(option_len));
    len+=sizeof(option_len);
    memcpy(OptinReq+len, &oprq1, sizeof(oprq1));
    len+=sizeof(oprq1);
    memcpy(OptinReq+len, &oprq2, sizeof(oprq2));
    len+=sizeof(oprq2);
    *size=len;
    return OptinReq;
}

static int add_option(int option, char *poption)
{
    unsigned short net_op = 0;
    net_op = htons(option);
    memcpy(poption, &net_op, sizeof(net_op));

    return 2;         //the option's len is 2
}

static int add_len(int len, char *plen)
{
    unsigned short net_len = 0;
    net_len = htons(len);
    memcpy(plen, &net_len, sizeof(net_len));

    return 2;      //the len's len is 2
}

static int add_value(unsigned char *value, int value_len, char *pvalue)
{
    memcpy(pvalue, value, value_len);

    return value_len;
}

