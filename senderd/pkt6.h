#ifndef __PKT6_H__
#define __PKT6_H__

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

#include <errno.h>            // errno, perror()

#include "libdiag.h"
#include "libnio.h"
#include "libdhcpv6.h"

// Define some constants.
#define ETH_HDRLEN 14  // Ethernet header length
#define IP6_HDRLEN 40  // IPv6 header length
#define UDP_HDRLEN  8  // UDP header length, excludes data

extern int getmac(char *ifname, char *mac);
extern int pkt6_eth(char *ifname, char *smac, char *dmac, uint16_t proto, uint8_t *data_ii);
extern int pkt6_ip(char *ifname, char *sip, char *dip, short proto, char hlim, int tc, char *data_iii, int payload_len);
extern int get_ipv6_by_ifname(char *ifname, char *ipv6);
extern int pkt6_udp(uint16_t sport, uint16_t dport, char *data_iiii, unsigned char *payload, int payload_len, struct ip6_hdr iphdr);
extern uint16_t udp6_checksum (struct ip6_hdr iphdr, struct udphdr udphdr, uint8_t *payload, int payloadlen);

#endif
