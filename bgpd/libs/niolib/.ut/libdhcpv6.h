#ifndef _LIBDHCPV6__H_
#define _LIBDHCPV6__H_

typedef struct dhcpv6_opt_st {
    unsigned short code;
    unsigned short len;
    char *value;
}dhcpv6_opt_t;

typedef struct dhcpv6_st {
    char msgtype;
    char transID[3];
    slist_t *opt_list;
}dhcpv6_t;

typedef struct relay_dhcpv6_st {
    char msgtype;

}relay_dhcpv6_t;

extern int request(nio_pkt_t *adv, char *pkt);
extern int solicit(char *duid, char *ifname, char *pkt, char *linkaddr);
extern int relay_solicit(char *sip, char *dip, char *linkaddr, char *client_mac, char *ifname, char *pkt);
extern int relay_request(nio_pkt_t *adv, char *pkt);

#endif
