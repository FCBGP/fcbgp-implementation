#include <stdio.h>
#include <stdlib.h>
#include <string.h> // strcpy, memset(), and memcpy()
#include <unistd.h> // close()

#include <arpa/inet.h>       // inet_pton() and inet_ntop()
#include <bits/ioctls.h>     // defines values for argument "request" of ioctl.
#include <linux/if_ether.h>  // ETH_P_IP = 0x0800, ETH_P_IPV6 = 0x86DD
#include <linux/if_packet.h> // struct sockaddr_ll (see man 7 packet)
#include <net/ethernet.h>
#include <net/if.h>      // struct ifreq
#include <netdb.h>       // struct addrinfo
#include <netinet/in.h>  // IPPROTO_UDP, INET6_ADDRSTRLEN
#include <netinet/ip.h>  // IP_MAXPACKET (which is 65535)
#include <netinet/ip6.h> // struct ip6_hdr
#include <netinet/udp.h> // struct udphdr
#include <sys/ioctl.h>   // macro ioctl is defined
#include <sys/socket.h>  // needed for socket()
#include <sys/types.h>   // needed for socket(), uint8_t, uint16_t

#include <errno.h> // errno, perror()

#include "libdhcpv6.h"
#include "libdiag.h"
#include "libnio.h"
#include "p4.h"

// Define some constants.
#define ETH_HDRLEN 14 // Ethernet header length
#define IP6_HDRLEN 40 // IPv6 header length
#define UDP_HDRLEN 8  // UDP header length, excludes data

// Function prototypes
uint16_t checksum(uint16_t*, int);
uint16_t udp6_checksum(struct ip6_hdr iphdr, struct udphdr udphdr,
                       uint8_t* payload, int payloadlen);
char* allocate_strmem(int);
uint8_t* allocate_ustrmem(int);

int getmac(char* ifname, char* mac, int size)
{
    struct ifreq ifr;
    int sockfd;

    memset(&ifr, 0, sizeof(ifr));
    strcpy(ifr.ifr_ifrn.ifrn_name, ifname);
    ifr.ifr_ifrn.ifrn_name[strlen(ifname)] = '\0';
    sockfd = socket(AF_INET6, SOCK_DGRAM, 0);
    if (sockfd == -1)
    {
        perror("socket");
    }
    if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) != 0)
    {
        perror("ioctl");
        close(sockfd);
        return -1;
    }
    close(sockfd);
    memcpy(mac, ifr.ifr_ifru.ifru_hwaddr.sa_data, 6);
    return 0;
}

int pkt6_eth(char* smac, char* dmac, uint16_t proto, uint8_t* data_ii)
{
    if (data_ii == NULL)
    {
        DIAG_ERROR("data_ii must not be NULL.\n");
        return -1;
    }

    // Destination and Source MAC addresses
    memcpy(data_ii, dmac, 6);
    memcpy(data_ii + 6, smac, 6);

    // Next is ethernet type code (ETH_P_IPV6 for IPv6).
    // http://www.iana.org/assignments/ethernet-numbers
    data_ii[12] = ETH_P_IPV6 >> 8;
    data_ii[13] = ETH_P_IPV6 & 0xff;

    return 0;
}

int pkt6_ip(char* sip, char* dip, short proto, char* data_iii, int payload_len)
{
    int ret;
    struct ip6_hdr* iphdr = (struct ip6_hdr*)data_iii;

    if (data_iii == NULL)
    {
        DIAG_ERROR("data_iii must not be NULL.\n");
        return -1;
    }

    // IPv6 header

    // IPv6 version (4 bits), Traffic class (8 bits), Flow label (20 bits)
    iphdr->ip6_flow = htonl((6 << 28) | (0 << 20) | 0);

    // Payload length (16 bits): UDP header + UDP data
    iphdr->ip6_plen = htons(UDP_HDRLEN + payload_len);

    // Next header (8 bits): 17 for UDP
    iphdr->ip6_nxt = proto;

    // Hop limit (8 bits): default to maximum value
    iphdr->ip6_hops = 255;

    // Source IPv6 address (128 bits)
    if ((ret = inet_pton(AF_INET6, sip, &(iphdr->ip6_src))) != 1)
    {
        DIAG_ERROR("inet_pton() failed.\nError message: %d", ret);
        return -1;
    }

    // Destination IPv6 address (128 bits)
    if ((ret = inet_pton(AF_INET6, dip, &(iphdr->ip6_dst))) != 1)
    {
        DIAG_ERROR("inet_pton() failed.\nError message: %d", ret);
        return -1;
    }

    return 0;
}

int pkt6_udp(uint16_t sport, uint16_t dport, char* data_iiii,
             unsigned char* payload, int payload_len, struct ip6_hdr iphdr)
{
    if (data_iiii == NULL)
    {
        DIAG_ERROR("data_iiii must not be NULL.\n");
        return -1;
    }

    // UDP header
    struct udphdr* udphdr = (struct udphdr*)data_iiii;

    // Source port number (16 bits): pick a number
    udphdr->source = htons(sport);

    // Destination port number (16 bits): pick a number
    udphdr->dest = htons(dport);

    // Length of UDP datagram (16 bits): UDP header + UDP data
    udphdr->len = htons(UDP_HDRLEN + payload_len);

    // UDP checksum (16 bits)
    udphdr->check = udp6_checksum(iphdr, *udphdr, payload, payload_len);

    return 0;
}

unsigned char* DUID(char* smac, int* size)
{
    unsigned short duid_type = 0;
    unsigned short hardware_type = 0;
    unsigned char time1[4];
    unsigned char duid[64] = {0};
    unsigned char* did = NULL;
    time_t now;
    unsigned long t;
    int len = 0;

    duid_type = htons(0x0001);
    hardware_type = htons(0x0001);
    now = time(NULL);
    printf("now is %ld.\n", now);
    // t = (unsigned long)now/4*1024*1024*1024;
    t = htonl(now);
    printf("t is %ld.\n", t);
    memcpy(time1, &t, sizeof(time1));
    memcpy(duid + len, &duid_type, sizeof(duid_type));
    len += sizeof(duid_type);
    memcpy(duid + len, &hardware_type, sizeof(hardware_type));
    len += sizeof(hardware_type);
    memcpy(duid + len, time1, sizeof(time1));
    len += sizeof(time1);
    memcpy(duid + len, smac, 6);
    len += 6;
    *size = len;
    did = (unsigned char*)malloc(len);
    memset(did, 0, len);
    memcpy(did, duid, len);
    return did;
}

unsigned char* ClientId(char* smac, int* size)
{ // cliId occupies 18 bytes
    unsigned short option_code = 0;
    unsigned short option_len = 0;
    unsigned char* duid = NULL;
    int duid_len = 0;
    unsigned char* clientId = NULL;
    int clientId_len = 0;

    option_code = htons(0x0001);
    option_len = htons(0x000e);
    clientId = (unsigned char*)malloc(18);
    memset(clientId, 0, 18);
    /* fill in option code */
    memcpy(clientId + clientId_len, &option_code, sizeof(option_code));
    clientId_len += sizeof(option_code);
    /* fill in option len */
    memcpy(clientId + clientId_len, &option_len, sizeof(option_len));
    clientId_len += sizeof(option_len);
    /* fill in DUID */
    duid = DUID(smac, &duid_len);
    if (duid == NULL)
    {
        printf("DUID fail\n");
        return NULL;
    }
    memcpy(clientId + clientId_len, duid, duid_len);
    clientId_len += duid_len;
    *size = clientId_len;
    free(duid);
    return clientId;
}

unsigned char* IaNa(char* smac, int* size)
{
    unsigned short option_code = htons(0x0003);
    unsigned short option_len = 0;
    unsigned char Iaid[4] = {0};
    unsigned char t1[4] = {0};
    unsigned char t2[4] = {0};
    unsigned char* Iana = NULL;
    int len = 0;

    option_len = htons(0x000c);
    memcpy(Iaid, smac + 2, sizeof(Iaid));
    t1[2] = 0x0e;
    t1[3] = 0x10;
    t2[2] = 0x15;
    t2[3] = 0x18;
    Iana = (unsigned char*)malloc(12 + 4);
    memset(Iana, 0, 12 + 4);
    memcpy(Iana + len, &option_code, sizeof(option_code));
    len += sizeof(option_code);
    memcpy(Iana + len, &option_len, sizeof(option_len));
    len += sizeof(option_len);
    memcpy(Iana + len, Iaid, sizeof(Iaid));
    len += sizeof(Iaid);
    memcpy(Iana + len, t1, sizeof(t1));
    len += sizeof(t1);
    memcpy(Iana + len, t2, sizeof(t2));
    len += sizeof(t2);
    *size = len;
    return Iana;
}

int myrand(unsigned char* ran, int len)
{
    unsigned int rd;
    unsigned char* p = (unsigned char*)&rd;

    if (len != 3)
    {
        printf("len %d invalid\n", len);
        return -1;
    }
    rd = rand();
    // printf("random is %x\n", rd);
    memcpy(ran, p, 3);

    return 0;
}

dhcpv6_relay_t* parse_relay_dhcp(unsigned char* dhcp, int len)
{
    unsigned char* p = dhcp;
    dhcpv6_relay_t* dhcpv6_relay_pkt;
    dhcpv6_relay_pkt = malloc(sizeof(dhcpv6_relay_t));
    if (dhcpv6_relay_pkt == NULL)
    {
        return NULL;
    }

    slist_t* list = malloc(sizeof(slist_t));
    ;
    slist_init(list);
    dhcpv6_relay_pkt->opt_list = list;
    dhcpv6_relay_pkt->msgtype = *p;
    p += 1;
    len -= 1;
    dhcpv6_relay_pkt->hopcount = *p;
    p += 1;
    len -= 1;
    memcpy(dhcpv6_relay_pkt->link_addr, p, 16);
    p += 16;
    len -= 16;
    memcpy(dhcpv6_relay_pkt->peer_addr, p, 16);
    p += 16;
    len -= 16;

    dhcpv6_opt_t* opt;

    while (len > 0)
    {
        opt = malloc(sizeof(dhcpv6_opt_t));
        opt->code = *p << 8 | *(p + 1);
        p += 2;
        len -= 2;
        opt->len = *p << 8 | *(p + 1);
        p += 2;
        len -= 2;
        opt->value = malloc(opt->len + 1);
        memcpy(opt->value, p, opt->len);
        p += opt->len;
        len -= opt->len;
        slist_add_tail(list, opt);
    }

    return dhcpv6_relay_pkt;
}

dhcpv6_t* parse_dhcp(unsigned char* dhcp, int len)
{
    unsigned char* p = dhcp;
    dhcpv6_t* dhcpv6_pkt;
    dhcpv6_pkt = malloc(sizeof(dhcpv6_t));
    if (dhcpv6_pkt == NULL)
    {
        return NULL;
    }

    slist_t* list = malloc(sizeof(slist_t));
    ;
    slist_init(list);
    dhcpv6_pkt->opt_list = list;
    dhcpv6_pkt->msgtype = *dhcp;
    p += 1;
    len -= 1;
    memcpy(dhcpv6_pkt->transID, p, 3);
    p += 3;
    len -= 3;

    dhcpv6_opt_t* opt;

    while (len > 0)
    {
        opt = malloc(sizeof(dhcpv6_opt_t));
        opt->code = *p << 8 | *(p + 1);
        p += 2;
        len -= 2;
        opt->len = *p << 8 | *(p + 1);
        p += 2;
        len -= 2;
        opt->value = malloc(opt->len + 1);
        memcpy(opt->value, p, opt->len);
        p += opt->len;
        len -= opt->len;
        slist_add_tail(list, opt);
    }

    return dhcpv6_pkt;
}

int get_opt(void* value, void* arg, int arg_len)
{
    dhcpv6_opt_t* opt = value;
    dhcpv6_opt_t* tmp = arg;
    if (opt->code == tmp->code)
    {
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
int get_option(slist_t* list, int optcode, char** value)
{
    dhcpv6_opt_t pkt_tmp;
    pkt_tmp.code = optcode;
    slist_foreach(list, get_opt, &pkt_tmp, sizeof(dhcpv6_opt_t));
    *value = pkt_tmp.value;
    return pkt_tmp.len;
}

void dhcp_option_fini(void* ptr)
{
    dhcpv6_opt_t* opt = ptr;
    free(opt->value);
    free(opt);
}

int parse_dhcp_relay_fini(dhcpv6_relay_t* pkt)
{
    slist_fini(pkt->opt_list, dhcp_option_fini);
    free(pkt->opt_list);
    free(pkt);
    return 0;
}

int parse_dhcp_fini(dhcpv6_t* pkt)
{
    slist_fini(pkt->opt_list, dhcp_option_fini);
    free(pkt->opt_list);
    free(pkt);
    return 0;
}

unsigned char* ElapseTime(int* size)
{
    unsigned short option_code = htons(0x0008);
    unsigned short option_len = htons(0x0002);
    unsigned char time[2] = {0xff, 0xff};
    unsigned char* elptime = NULL;
    int len = 0;

    elptime = (unsigned char*)malloc(6);
    memset(elptime, 0, 6);
    memcpy(elptime + len, &option_code, sizeof(option_code));
    len += sizeof(option_code);
    memcpy(elptime + len, &option_len, sizeof(option_len));
    len += sizeof(option_len);
    memcpy(elptime + len, time, sizeof(time));
    len += sizeof(time);
    *size = len;
    return elptime;
}

unsigned char* OptinReq(int* size)
{
    unsigned short option_code = htons(0x0006);
    unsigned short option_len = htons(0x0004);
    unsigned short oprq1 = htons(0x0017);
    unsigned short oprq2 = htons(0x0018);
    unsigned char* OptinReq = NULL;
    int len = 0;

    OptinReq = (unsigned char*)malloc(8);
    memset(OptinReq, 0, 8);
    memcpy(OptinReq + len, &option_code, sizeof(option_code));
    len += sizeof(option_code);
    memcpy(OptinReq + len, &option_len, sizeof(option_len));
    len += sizeof(option_len);
    memcpy(OptinReq + len, &oprq1, sizeof(oprq1));
    len += sizeof(oprq1);
    memcpy(OptinReq + len, &oprq2, sizeof(oprq2));
    len += sizeof(oprq2);
    *size = len;
    return OptinReq;
}

int pkt6_request(unsigned char* dhcp, int dhcp_len, char* request, int* reqlen)
{
    unsigned char msg_type = 0x03;
    unsigned short option_code = 0;
    unsigned short option_len = 0;
    int len = 0;
    int ret = 0;
    // char nidstr[16]={0};

    dhcpv6_t* dhc6;
    dhc6 = parse_dhcp(dhcp, dhcp_len);
    if (dhc6 == NULL)
    {
        DIAG_ERROR("parse dhcp failed.\n");
        return -1;
    }
    /* fill in msg type */
    memcpy(request + len, &msg_type, sizeof(msg_type));
    len += sizeof(msg_type);
    /* fill in tran_id */
    memcpy(request + len, dhcp + 1, 3);
    len += 3;
    /* fill in Client identifier option */

    //    ClientIdm=ClientId(smac, &ClientId_len);
    //    if(ClientId==NULL){
    //        printf("Generate ClientId fail\n");
    //        return -1;
    //    }

    char** value = NULL;
    char* tmp;
    value = &tmp;

    ret = get_option(dhc6->opt_list, 0x01, value);

    option_code = htons(0x01);
    memcpy(request + len, &option_code, sizeof(option_code));
    len += sizeof(option_code);
    option_len = htons(ret);
    memcpy(request + len, &option_len, sizeof(option_len));
    len += sizeof(option_len);
    memcpy(request + len, *value, ret);
    len += ret;
    // free(ClientIdm);
    /* fill in Server identifier option */
    ret = get_option(dhc6->opt_list, 0x02, value);
    option_code = htons(0x02);
    memcpy(request + len, &option_code, sizeof(option_code));
    len += sizeof(option_code);
    option_len = htons(ret);
    memcpy(request + len, &option_len, sizeof(option_len));
    len += sizeof(option_len);
    memcpy(request + len, *value, ret);
    len += ret;

    //   //free(ServId);
    //   /* fill in Option request */
    //   Optionreqm=OptinReq(&Optionreq_len);
    //   if(Optionreqm==NULL){
    //       printf("Generate Optionreq fail\n");
    //       return -1;
    //   }
    //    memcpy(request+len, Optionreqm, Optionreq_len);
    //    len+=Optionreq_len;
    // free(Optionreqm);
    //   /* fill in Elapsed time option */
    //   ElapseTimem=ElapseTime(&ElapseTime_len);
    //   if(ElapseTimem==NULL){
    //       printf("Generate ElapseTime fail\n");
    //       return -1;
    //   }
    //   memcpy(request+len, ElapseTimem, ElapseTime_len);
    //   len+=ElapseTime_len;
    // free(ElapseTimem);
    /* fill in IA_NA option  */
    ret = get_option(dhc6->opt_list, 0x03, value);
    option_code = htons(0x03);
    memcpy(request + len, &option_code, sizeof(option_code));
    len += sizeof(option_code);
    option_len = htons(ret);
    memcpy(request + len, &option_len, sizeof(option_len));
    len += sizeof(option_len);
    memcpy(request + len, *value, ret);
    len += ret;

    //   /* fill in digest option */
    //   digest=Digest(nonce , nonce_len, &digest_len);
    //   if(digest==NULL){
    //       printf("Digest fail\n");
    //       return -1;
    //   }
    //   memcpy(request+len, digest, digest_len);
    //   len+=digest_len;
    // free(digest);
    /* fill in mac option */
    //   if(getmac(eth, mac, sizeof(mac))!=0)
    //       return -1;
    //   option_code=htons(0x1006);
    //   option_len=htons(0x0006);
    //   memcpy(request+len, &option_code, sizeof(option_code));
    //   len+=sizeof(option_code);
    //   memcpy(request+len, &option_len, sizeof(option_len));
    //   len+=sizeof(option_len);
    //   memcpy(request+len, mac, sizeof(mac));
    //   len+=sizeof(mac);
    if (*reqlen < len)
    {
        printf("Generate request msg fail ,  reqlen %d < len %d\n", *reqlen,
               len);
        return -1;
    }
    *reqlen = len;
    parse_dhcp_fini(dhc6);
    return 0;
}

static int add_request_option(char* addr)
{
    unsigned short option = 0x06;
    unsigned short len = 8;
    char option_request[32] = {
        0x00, 0x11, 0x00, 0x17, 0x00,
        0x18, 0x00, 0x27}; // vendor, dns, domain, fully qualified domain name.
    memcpy(addr, &option, sizeof(option));
    len += sizeof(option);
    memcpy(addr + len, &len, sizeof(len));
    len += sizeof(len);
    memcpy(addr + len, option_request, 8);
    len += 8;

    return len;
}

int dhcp6_pkt6_request(unsigned char* dhcp, int dhcp_len, char* request,
                       int* reqlen)
{
    unsigned char msg_type = 0x03;
    unsigned short option_code = 0;
    unsigned short option_len = 0;
    int len = 0;
    int ret = 0;
    // char nidstr[16]={0};

    dhcpv6_t* dhc6;
    dhc6 = parse_dhcp(dhcp, dhcp_len);
    if (dhc6 == NULL)
    {
        DIAG_ERROR("parse dhcp failed.\n");
        return -1;
    }
    /* fill in msg type */
    memcpy(request + len, &msg_type, sizeof(msg_type));
    len += sizeof(msg_type);
    /* fill in tran_id */
    memcpy(request + len, dhcp + 1, 3);
    len += 3;
    /* fill in Client identifier option */

    //    ClientIdm=ClientId(smac, &ClientId_len);
    //    if(ClientId==NULL){
    //        printf("Generate ClientId fail\n");
    //        return -1;
    //    }

    char** value = NULL;
    char* tmp;
    value = &tmp;

    ret = get_option(dhc6->opt_list, 0x01, value);

    option_code = htons(0x01);
    memcpy(request + len, &option_code, sizeof(option_code));
    len += sizeof(option_code);
    option_len = htons(ret);
    memcpy(request + len, &option_len, sizeof(option_len));
    len += sizeof(option_len);
    memcpy(request + len, *value, ret);
    len += ret;
    // free(ClientIdm);
    /* fill in Server identifier option */
    ret = get_option(dhc6->opt_list, 0x02, value);
    option_code = htons(0x02);
    memcpy(request + len, &option_code, sizeof(option_code));
    len += sizeof(option_code);
    option_len = htons(ret);
    memcpy(request + len, &option_len, sizeof(option_len));
    len += sizeof(option_len);
    memcpy(request + len, *value, ret);
    len += ret;

    //   //free(ServId);
    //   /* fill in Option request */
    //   Optionreqm=OptinReq(&Optionreq_len);
    //   if(Optionreqm==NULL){
    //       printf("Generate Optionreq fail\n");
    //       return -1;
    //   }
    //    memcpy(request+len, Optionreqm, Optionreq_len);
    //    len+=Optionreq_len;
    // free(Optionreqm);
    //   /* fill in Elapsed time option */
    //   ElapseTimem=ElapseTime(&ElapseTime_len);
    //   if(ElapseTimem==NULL){
    //       printf("Generate ElapseTime fail\n");
    //       return -1;
    //   }
    //   memcpy(request+len, ElapseTimem, ElapseTime_len);
    //   len+=ElapseTime_len;
    // free(ElapseTimem);
    /* fill in IA_NA option  */
    ret = get_option(dhc6->opt_list, 0x03, value);
    option_code = htons(0x03);
    memcpy(request + len, &option_code, sizeof(option_code));
    len += sizeof(option_code);
    option_len = htons(ret);
    memcpy(request + len, &option_len, sizeof(option_len));
    len += sizeof(option_len);
    memcpy(request + len, *value, ret);
    len += ret;

    //   /* fill in digest option */
    //   digest=Digest(nonce , nonce_len, &digest_len);
    //   if(digest==NULL){
    //       printf("Digest fail\n");
    //       return -1;
    //   }
    //   memcpy(request+len, digest, digest_len);
    //   len+=digest_len;
    // free(digest);
    /* fill in mac option */
    //   if(getmac(eth, mac, sizeof(mac))!=0)
    //       return -1;
    //   option_code=htons(0x1006);
    //   option_len=htons(0x0006);
    //   memcpy(request+len, &option_code, sizeof(option_code));
    //   len+=sizeof(option_code);
    //   memcpy(request+len, &option_len, sizeof(option_len));
    //   len+=sizeof(option_len);
    //   memcpy(request+len, mac, sizeof(mac));
    //   len+=sizeof(mac);
    /* fill in request option*/
    ret = add_request_option(request + len);
    len += ret;

    if (*reqlen < len)
    {
        printf("Generate request msg fail ,  reqlen %d < len %d\n", *reqlen,
               len);
        return -1;
    }
    *reqlen = len;
    parse_dhcp_fini(dhc6);
    return 0;
}

int relay_pkt6_request(unsigned char* dhcp, int dhcp_len, char* request,
                       int* reqlen)
{
    unsigned char msg_type = 0x0c;
    unsigned short option_code = 0;
    unsigned short option_len = 0;
    int len = 0;
    int ret = 0;
    // char nidstr[16]={0};

    dhcpv6_relay_t* dhc6;
    dhc6 = parse_relay_dhcp(dhcp, dhcp_len);
    if (dhc6 == NULL)
    {
        DIAG_ERROR("parse dhcp failed.\n");
        return -1;
    }
    /* copy msgtype, Hopcount, link address, peer address*/
    /* fill in msg type */
    memcpy(request + len, &msg_type, sizeof(msg_type));
    len += sizeof(msg_type);

    memcpy(request + len, &dhc6->hopcount, 1);
    len += 1;
    memcpy(request + len, dhc6->link_addr, 16);
    len += 16;
    memcpy(request + len, dhc6->peer_addr, 16);
    len += 16;

    /* fill in Client identifier option */

    //    ClientIdm=ClientId(smac, &ClientId_len);
    //    if(ClientId==NULL){
    //        printf("Generate ClientId fail\n");
    //        return -1;
    //    }

    char** value = NULL;
    char* tmp;
    value = &tmp;
#if 0
    /* interface id */
    ret = get_option(dhc6->opt_list, 0x12, value);
    option_code = htons(0x12);
    memcpy(request+len, &option_code, sizeof(option_code));
    len += sizeof(option_code);
    option_len = htons(ret);
    memcpy(request+len, &option_len, sizeof(option_len));
    len += sizeof(option_len);
    memcpy(request+len, *value, ret);
    len += ret;
    //free(ClientIdm);
#endif

#if 0
    /* fill in Server identifier option */
    ret = get_option(dhc6->opt_list, 0x02, value);
    option_code = htons(0x02);
    memcpy(request+len, &option_code, sizeof(option_code));
    len += sizeof(option_code);
    option_len = htons(ret);
    memcpy(request+len, &option_len, sizeof(option_len));
    len += sizeof(option_len);
    memcpy(request+len, *value, ret);
    len += ret;
#endif

    //   //free(ServId);
    //   /* fill in Option request */
    //   Optionreqm=OptinReq(&Optionreq_len);
    //   if(Optionreqm==NULL){
    //       printf("Generate Optionreq fail\n");
    //       return -1;
    //   }
    //    memcpy(request+len, Optionreqm, Optionreq_len);
    //    len+=Optionreq_len;
    // free(Optionreqm);
    //   /* fill in Elapsed time option */
    //   ElapseTimem=ElapseTime(&ElapseTime_len);
    //   if(ElapseTimem==NULL){
    //       printf("Generate ElapseTime fail\n");
    //       return -1;
    //   }
    //   memcpy(request+len, ElapseTimem, ElapseTime_len);
    //   len+=ElapseTime_len;
    // free(ElapseTimem);
    /* fill in relay message option  */
    ret = get_option(dhc6->opt_list, 0x09, value);
    option_code = htons(0x09);
    memcpy(request + len, &option_code, sizeof(option_code));
    len += sizeof(option_code);

    char dhcp_request[1024] = {0};
    int dhcp_request_len = sizeof(dhcp_request);
    dhcp6_pkt6_request((unsigned char*)*value, ret, dhcp_request,
                       &dhcp_request_len);

    option_len = htons(dhcp_request_len);
    memcpy(request + len, &option_len, sizeof(option_len));
    len += sizeof(option_len);

    memcpy(request + len, dhcp_request, dhcp_request_len);
    len += dhcp_request_len;

    if (*reqlen < len)
    {
        printf("Generate request msg fail ,  reqlen %d < len %d\n", *reqlen,
               len);
        return -1;
    }
    *reqlen = len;
    parse_dhcp_relay_fini(dhc6);
    return 0;
}

int pkt6_solicit(unsigned char* solicit, int* solicit_len, char* smac)
{
    if (solicit == NULL)
    {
        DIAG_ERROR("solicit must not be NULL.\n");
        return -1;
    }

    unsigned char msg_type = 0x01;
    unsigned char tran_id[3] = {0};
    int len = 0;
    unsigned char* ClientIdm = NULL;
    int ClientId_len = 0;
    unsigned char* Optionreqm = NULL;
    int Optionreq_len = 0;
    unsigned char* ElapseTimem = NULL;
    int ElapseTime_len = 0;
    unsigned char* Ianam = NULL;
    int Iana_len = 0;
    // char nidstr[16]={0};

    /* fill in msg type */
    memcpy(solicit + len, &msg_type, sizeof(msg_type));
    len += sizeof(msg_type);
    /* fill in tran_id */
    if (myrand(tran_id, 3) != 0)
    {
        printf("myrand fail\n");
        return -1;
    }
    memcpy(solicit + len, tran_id, sizeof(tran_id));
    len += sizeof(tran_id);
    /* fill in Client identifier option */
    ClientIdm = ClientId(smac, &ClientId_len);
    if (ClientIdm == NULL)
    {
        printf("Generate ClientId fail\n");
        return -1;
    }
    memcpy(solicit + len, ClientIdm, ClientId_len);
    len += ClientId_len;
    free(ClientIdm);
    /* fill in Option request option */
    Optionreqm = OptinReq(&Optionreq_len);
    if (Optionreqm == NULL)
    {
        printf("Generate Optionreq fail\n");
        return -1;
    }
    memcpy(solicit + len, Optionreqm, Optionreq_len);
    len += Optionreq_len;
    free(Optionreqm);
    /* fill in Elapsed time option */
    ElapseTimem = ElapseTime(&ElapseTime_len);
    if (ElapseTimem == NULL)
    {
        printf("Generate ElapseTime fail\n");
        return -1;
    }
    memcpy(solicit + len, ElapseTimem, ElapseTime_len);
    len += ElapseTime_len;
    free(ElapseTimem);
    /* fill in IA_NA option  */
    Ianam = IaNa(smac, &Iana_len);
    if (Ianam == NULL)
    {
        printf("Generate Iana fail\n");
        return -1;
    }
    memcpy(solicit + len, Ianam, Iana_len);
    len += Iana_len;
    free(Ianam);
    /* fill in Nid option
     *     if(get_nid(nidstr)!=0){
     *              printf("get_nid fail\n");
     *                       return -1;
     *                           }
     *                               */
    //   Nidm=Nid(nidstr, strlen(nidstr));
    //   if(Nidm==NULL){
    //       printf("Generate Nid fail\n");
    //       return -1;
    //   }
    //   memcpy(solicit+len, Nidm, 9);
    //   len+=9;
    //   free(Nidm);
    if (*solicit_len < len)
    {
        printf("mem of solicit : %d too small\n", len);
        return -1;
    }
    *solicit_len = len;

    return 0;
}

static int add_option(int option, char* poption)
{
    unsigned short net_op = 0;
    net_op = htons(option);
    memcpy(poption, &net_op, sizeof(net_op));

    return 2; // the option's len is 2
}

static int add_len(int len, char* plen)
{
    unsigned short net_len = 0;
    net_len = htons(len);
    memcpy(plen, &net_len, sizeof(net_len));

    return 2; // the len's len is 2
}

static int add_value(unsigned char* value, int value_len, char* pvalue)
{
    memcpy(pvalue, value, value_len);

    return value_len;
}

static char* add_option79(char* mac)
{
    char* client_mac = NULL;
    int len = 0;
    unsigned char mac_type[16] = {};
    int i = 0;
    int ret = 0;

    client_mac = malloc(16);
    memset(client_mac, 0, 16);

    ret = add_option(79, client_mac + len);
    len += ret;
    ret = add_len(8, client_mac + len);
    len += ret;
    mac_type[0] = 0x00;
    mac_type[1] = 0x01;

    for (i = 0; i < 6; i++)
    {
        mac_type[i + 2] = mac[i];
    }

    ret = add_value(mac_type, 8, client_mac + len);
    len += ret;

    return client_mac;
}

int pkt6_relay_solicit(char* sip, char* linkaddr, char* client_mac,
                       char* payload, int* payload_len)
{
    unsigned char msg_type = 0x0c;
    unsigned char hopcount = 0x0;
    int len = 0;
    unsigned char buf[sizeof(struct in6_addr)];
    char* client_link_layer = NULL;
    unsigned char solicit[1024] = {
        0,
    };
    int solicit_len = 1024;
    int ret = 0;

    if (payload == NULL)
    {
        DIAG_ERROR("payload must not be NULL.\n");
        return -1;
    }

    // char nidstr[16]={0};

    /* fill in msg type */
    memcpy(payload + len, &msg_type, sizeof(msg_type));
    len += sizeof(msg_type);

    /* fill in hopcount  but i don't now what is this*/
    memcpy(payload + len, &hopcount, sizeof(hopcount));
    len += sizeof(hopcount);

    /*fill in link addr no fe80 address*/
    ret = inet_pton(AF_INET6, sip, buf);
    if (ret != 1)
    {
        DIAG_ERROR("inet_pton() failed.\nError message: %d", ret);
        return -1;
    }

    memcpy(payload + len, buf, sizeof(buf));
    len += sizeof(buf);

    /*fill in link addr fe80 address*/
    ret = inet_pton(AF_INET6, linkaddr, buf);
    if (ret != 1)
    {
        DIAG_ERROR("inet_pton() failed.\nError message: %d", ret);
        return -1;
    }

    memcpy(payload + len, buf, sizeof(buf));
    len += sizeof(buf);

    /* fill in client link-layer address */
    client_link_layer = add_option79(client_mac);
    if (client_link_layer == NULL)
    {
        printf("Generate Optionreq fail\n");
        return -1;
    }
    memcpy(payload + len, client_link_layer, 12);
    len += 12;
    free(client_link_layer);

    ret = add_option(9, payload + len);
    len += ret;
    pkt6_solicit(solicit, &solicit_len, client_mac);
    ret = add_len(solicit_len, payload + len);
    len += ret;
    ret = add_value(solicit, solicit_len, payload + len);
    len += ret;

    *payload_len = len;
    return 0;
}

int solicit(char* duid, char* ifname, char* pkt, char* linkaddr)
{
    int offset = 0;
    unsigned char payload[1024] = {
        0,
    };
    int payload_len = sizeof(payload);
    struct udphdr udphdr;
    struct ip6_hdr iphdr;
    unsigned char data_eth[32] = {
        0,
    };

    pkt6_solicit(payload, &payload_len, duid);

    pkt6_ip(linkaddr, "ff02::1:2", IPPROTO_UDP, (char*)&iphdr, payload_len);
    pkt6_udp(546, 547, (char*)&udphdr, payload, payload_len, iphdr);

    char smac[6] = {
        0,
    };
    if (getmac(ifname, smac, sizeof(smac)) < 0)
    {
        return -1;
    }

    char dmac[6] = {0x33, 0x33, 0x00, 0x01, 0x00, 0x02};
    pkt6_eth(smac, dmac, 0x86dd, data_eth);

    memcpy(pkt, data_eth, ETH_HDRLEN);
    offset += ETH_HDRLEN;
    memcpy(pkt + offset, &iphdr, IP6_HDRLEN);
    offset += IP6_HDRLEN;
    memcpy(pkt + offset, &udphdr, UDP_HDRLEN);
    offset += UDP_HDRLEN;
    memcpy(pkt + offset, payload, payload_len);
    offset += payload_len;

    return offset;
}

int relay_solicit(char* sip, char* dip, char* linkaddr, char* client_mac,
                  char* ifname, char* pkt)
{
    int offset = 0;
    char payload[1024] = {
        0,
    };
    int payload_len = sizeof(payload);
    struct udphdr udphdr;
    struct ip6_hdr iphdr;
    unsigned char data_eth[32] = {
        0,
    };

    pkt6_relay_solicit(sip, linkaddr, client_mac, payload, &payload_len);

    pkt6_ip(linkaddr, dip, IPPROTO_UDP, (char*)&iphdr, payload_len);
    pkt6_udp(546, 547, (char*)&udphdr, (unsigned char*)payload, payload_len,
             iphdr);

    char smac[6] = {
        0,
    };
    if (getmac(ifname, smac, sizeof(smac)) < 0)
    {
        return -1;
    }

    char dmac[6] = {0x33, 0x33, 0x00, 0x01, 0x00, 0x02};
    pkt6_eth(smac, dmac, 0x86dd, data_eth);

    memcpy(pkt, data_eth, ETH_HDRLEN);
    offset += ETH_HDRLEN;
    memcpy(pkt + offset, &iphdr, IP6_HDRLEN);
    offset += IP6_HDRLEN;
    memcpy(pkt + offset, &udphdr, UDP_HDRLEN);
    offset += UDP_HDRLEN;
    memcpy(pkt + offset, payload, payload_len);
    offset += payload_len;

    return offset;
}

int request(nio_pkt_t* adv, char* pkt)
{
    int offset = 0;
    unsigned char payload[1024] = {
        0,
    };
    int payload_len = sizeof(payload);
    struct udphdr udphdr;
    struct ip6_hdr iphdr;
    unsigned char data_eth[32] = {
        0,
    };
    char sip[64] = {
        0,
    };
    char dip[64] = {
        0,
    };
    int i;
    char* tmp;
    int data_len = adv->length - 62;

    pkt6_request((unsigned char*)adv->data + 62, data_len, (char*)payload,
                 &payload_len);
    tmp = sip;
    for (i = 0; i < 16; i += 2)
    {
        sprintf(tmp, "%02x", *(adv->data + 38 + i));
        tmp += 2;
        sprintf(tmp, "%02x", *(adv->data + 38 + i + 1));
        tmp += 2;
        if (i != 14)
        {
            *tmp++ = ':';
        }
    }

    tmp = dip;
    for (i = 0; i < 16; i += 2)
    {
        sprintf(tmp, "%02x", *(adv->data + 22 + i));
        tmp += 2;
        sprintf(tmp, "%02x", *(adv->data + 22 + i + 1));
        tmp += 2;
        if (i != 14)
        {
            *tmp++ = ':';
        }
    }

    pkt6_ip(sip, dip, IPPROTO_UDP, (char*)&iphdr, payload_len);
    pkt6_udp(546, 547, (char*)&udphdr, payload, payload_len, iphdr);

    char dmac[6] = {
        0,
    };
    memcpy(dmac, adv->data + 6, 6);
    char smac[6] = {
        0,
    };
    memcpy(smac, adv->data, 6);
    pkt6_eth(smac, dmac, 0x86dd, data_eth);

    memcpy(pkt, data_eth, ETH_HDRLEN);
    offset += ETH_HDRLEN;
    memcpy(pkt + offset, &iphdr, IP6_HDRLEN);
    offset += IP6_HDRLEN;
    memcpy(pkt + offset, &udphdr, UDP_HDRLEN);
    offset += UDP_HDRLEN;
    memcpy(pkt + offset, payload, payload_len);
    offset += payload_len;

    return offset;
}

int relay_request(nio_pkt_t* adv, char* pkt)
{
    int offset = 0;
    unsigned char payload[1024] = {
        0,
    };
    int payload_len = sizeof(payload);
    struct udphdr udphdr;
    struct ip6_hdr iphdr;
    unsigned char data_eth[32] = {
        0,
    };
    char sip[64] = {
        0,
    };
    char dip[64] = {
        0,
    };
    int i;
    char* tmp;
    int data_len = adv->length - 62;

    relay_pkt6_request((unsigned char*)adv->data + 62, data_len, (char*)payload,
                       &payload_len);
    tmp = sip;
    for (i = 0; i < 16; i += 2)
    {
        sprintf(tmp, "%02x", *(adv->data + 38 + i));
        tmp += 2;
        sprintf(tmp, "%02x", *(adv->data + 38 + i + 1));
        tmp += 2;
        if (i != 14)
        {
            *tmp++ = ':';
        }
    }

    tmp = dip;
    for (i = 0; i < 16; i += 2)
    {
        sprintf(tmp, "%02x", *(adv->data + 22 + i));
        tmp += 2;
        sprintf(tmp, "%02x", *(adv->data + 22 + i + 1));
        tmp += 2;
        if (i != 14)
        {
            *tmp++ = ':';
        }
    }

    pkt6_ip(sip, dip, IPPROTO_UDP, (char*)&iphdr, payload_len);
    pkt6_udp(547, 547, (char*)&udphdr, payload, payload_len, iphdr);

    char dmac[6] = {
        0,
    };
    memcpy(dmac, adv->data + 6, 6);
    char smac[6] = {
        0,
    };
    memcpy(smac, adv->data, 6);
    pkt6_eth(smac, dmac, 0x86dd, data_eth);

    memcpy(pkt, data_eth, ETH_HDRLEN);
    offset += ETH_HDRLEN;
    memcpy(pkt + offset, &iphdr, IP6_HDRLEN);
    offset += IP6_HDRLEN;
    memcpy(pkt + offset, &udphdr, UDP_HDRLEN);
    offset += UDP_HDRLEN;
    memcpy(pkt + offset, payload, payload_len);
    offset += payload_len;

    return offset;
}

// Computing the internet checksum (RFC 1071).
// Note that the internet checksum does not preclude collisions.
uint16_t checksum(uint16_t* addr, int len)
{
    int count = len;
    register uint32_t sum = 0;
    uint16_t answer = 0;

    // Sum up 2-byte values until none or only one byte left.
    while (count > 1)
    {
        sum += *(addr++);
        count -= 2;
    }

    // Add left-over byte, if any.
    if (count > 0)
    {
        sum += *(uint8_t*)addr;
    }

    // Fold 32-bit sum into 16 bits; we lose information by doing this,
    // increasing the chances of a collision.
    // sum = (lower 16 bits) + (upper 16 bits shifted right 16 bits)
    while (sum >> 16)
    {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    // Checksum is one's compliment of sum.
    answer = ~sum;

    return (answer);
}

// Build IPv6 UDP pseudo-header and call checksum function (Section 8.1 of RFC
// 2460).
uint16_t udp6_checksum(struct ip6_hdr iphdr, struct udphdr udphdr,
                       uint8_t* payload, int payloadlen)
{
    char buf[IP_MAXPACKET];
    char* ptr;
    int chksumlen = 0;
    int i;

    ptr = &buf[0]; // ptr points to beginning of buffer buf

    // Copy source IP address into buf (128 bits)
    memcpy(ptr, &iphdr.ip6_src.s6_addr, sizeof(iphdr.ip6_src.s6_addr));
    ptr += sizeof(iphdr.ip6_src.s6_addr);
    chksumlen += sizeof(iphdr.ip6_src.s6_addr);

    // Copy destination IP address into buf (128 bits)
    memcpy(ptr, &iphdr.ip6_dst.s6_addr, sizeof(iphdr.ip6_dst.s6_addr));
    ptr += sizeof(iphdr.ip6_dst.s6_addr);
    chksumlen += sizeof(iphdr.ip6_dst.s6_addr);

    // Copy UDP length into buf (32 bits)
    memcpy(ptr, &udphdr.len, sizeof(udphdr.len));
    ptr += sizeof(udphdr.len);
    chksumlen += sizeof(udphdr.len);

    // Copy zero field to buf (24 bits)
    *ptr = 0;
    ptr++;
    *ptr = 0;
    ptr++;
    *ptr = 0;
    ptr++;
    chksumlen += 3;

    // Copy next header field to buf (8 bits)
    memcpy(ptr, &iphdr.ip6_nxt, sizeof(iphdr.ip6_nxt));
    ptr += sizeof(iphdr.ip6_nxt);
    chksumlen += sizeof(iphdr.ip6_nxt);

    // Copy UDP source port to buf (16 bits)
    memcpy(ptr, &udphdr.source, sizeof(udphdr.source));
    ptr += sizeof(udphdr.source);
    chksumlen += sizeof(udphdr.source);

    // Copy UDP destination port to buf (16 bits)
    memcpy(ptr, &udphdr.dest, sizeof(udphdr.dest));
    ptr += sizeof(udphdr.dest);
    chksumlen += sizeof(udphdr.dest);

    // Copy UDP length again to buf (16 bits)
    memcpy(ptr, &udphdr.len, sizeof(udphdr.len));
    ptr += sizeof(udphdr.len);
    chksumlen += sizeof(udphdr.len);

    // Copy UDP checksum to buf (16 bits)
    // Zero, since we don't know it yet
    *ptr = 0;
    ptr++;
    *ptr = 0;
    ptr++;
    chksumlen += 2;

    // Copy payload to buf
    memcpy(ptr, payload, payloadlen * sizeof(uint8_t));
    ptr += payloadlen;
    chksumlen += payloadlen;

    // Pad to the next 16-bit boundary
    for (i = 0; i < payloadlen % 2; i++, ptr++)
    {
        *ptr = 0;
        ptr++;
        chksumlen++;
    }

    return checksum((uint16_t*)buf, chksumlen);
}

// Allocate memory for an array of chars.
char* allocate_strmem(int len)
{
    void* tmp;

    if (len <= 0)
    {
        fprintf(stderr,
                "ERROR: Cannot allocate memory because len = %i in "
                "allocate_strmem().\n",
                len);
        exit(EXIT_FAILURE);
    }

    tmp = (char*)malloc(len * sizeof(char));
    if (tmp != NULL)
    {
        memset(tmp, 0, len * sizeof(char));
        return (tmp);
    }
    else
    {
        fprintf(stderr,
                "ERROR: Cannot allocate memory for array allocate_strmem().\n");
        exit(EXIT_FAILURE);
    }
}

// Allocate memory for an array of unsigned chars.
uint8_t* allocate_ustrmem(int len)
{
    void* tmp;

    if (len <= 0)
    {
        fprintf(stderr,
                "ERROR: Cannot allocate memory because len = %i in "
                "allocate_ustrmem().\n",
                len);
        exit(EXIT_FAILURE);
    }

    tmp = (uint8_t*)malloc(len * sizeof(uint8_t));
    if (tmp != NULL)
    {
        memset(tmp, 0, len * sizeof(uint8_t));
        return (tmp);
    }
    else
    {
        fprintf(
            stderr,
            "ERROR: Cannot allocate memory for array allocate_ustrmem().\n");
        exit(EXIT_FAILURE);
    }
}
