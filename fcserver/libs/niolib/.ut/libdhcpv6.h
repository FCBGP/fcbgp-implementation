#ifndef _LIBDHCPV6__H_
#define _LIBDHCPV6__H_

typedef struct dhcpv6_opt_st
{
    unsigned short code;
    unsigned short len;
    char* value;
} dhcpv6_opt_t;

typedef struct dhcpv6_st
{
    char msgtype;
    char transID[3];
    slist_t* opt_list;
} dhcpv6_t;

typedef struct dhcpv6_relay_st
{
    char msgtype;
    char hopcount;
    char link_addr[16];
    char peer_addr[16];
    slist_t* opt_list;
} dhcpv6_relay_t;

typedef struct dhcpv6_msg_st
{
    char* ifname;
    int count;
    char loop;
} dhcpv6_msg_t;

typedef struct relay_dhcpv6_st
{
    char msgtype;

} relay_dhcpv6_t;

extern int request(nio_pkt_t* adv, char* pkt);
extern int solicit(char* duid, char* ifname, char* pkt, char* linkaddr);
extern int relay_solicit(char* sip, char* dip, char* linkaddr, char* client_mac,
                         char* ifname, char* pkt);
extern int relay_request(nio_pkt_t* adv, char* pkt);
extern dhcpv6_relay_t* parse_relay_dhcp(unsigned char* dhcp, int len);
extern int get_option(slist_t* list, int optcode, char** value);
extern dhcpv6_t* parse_dhcp(unsigned char* dhcp, int len);
extern int parse_dhcp_relay_fini(dhcpv6_relay_t* pkt);
extern int parse_dhcp_fini(dhcpv6_t* pkt);

#endif
