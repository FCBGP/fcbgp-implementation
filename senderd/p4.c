#include "p4.h"
#include <errno.h>
#include "libdiag.h"
#include "pkt6.h"
#include "hex.h"
#include "libmd5.h"
#include "libcrc32.h"

extern uint8_t g_scanner_sip6[64];
extern uint8_t g_scanner_dip6[64];

int print_pkt(unsigned char *start, unsigned char *end)
{
    int i=0;
    if(start > end) {
        return -1;
    }

    unsigned char *c = NULL;
    for(c=start, i=0; c<end; c++, i++) {
        if(i % 16 == 0) {
            printf("\n");
        } else if (i%8 == 0) {
            printf("  ");
        } else if (i%4 == 0) {
            printf(" ");
        }
        printf("%02X ", *c);
    }
    printf("\n");

    return end - start;
}

int gen_datahash(unsigned char *sid, char ttl, char* payload, unsigned char *digest)
{
    int ret = 0;
    int offset = 0;
    char buf[512] = {0};
    memset(buf, 0, sizeof(buf));
    memcpy(buf, sid, 12); offset += 12;
    memcpy(buf+offset, &ttl, 1); offset += 1;
    memcpy(buf+offset, payload, strlen(payload)); offset+=strlen(payload);
    ret = strmd5digest(buf, digest);
    return ret;
}

int gen_sid(char *sip, char *dip, char *key, unsigned char *digest)
{
    int ret = 0;
    int offset = 0;
    char buf[512] = {0};
    memset(buf, 0, sizeof(buf));
    memcpy(buf+offset, sip, strlen(sip));         offset += strlen(sip);
    memcpy(buf+offset, dip, strlen(dip));         offset += strlen(dip);
    memcpy(buf+offset, key, strlen(key));offset += strlen(key);
    ret = strmd5digest(buf, digest);
//    digest[12] = '\0';
    return ret;
}

int gen_mac(unsigned char *datahash, char *node_key, char *MAC)
{
    int ret = 0;
    return ret;
}

int get_keystr_by_indi(uint32_t indi, unsigned char *res)
{
    int i =0;
    char indi_str[64] = {0};
    char key_str[64] = {0};
    struct in_addr indi_res = {0};
    cJSON *tmp  = NULL;
    if(res == NULL) {
        return -1;
    }

    cJSON *hosts = cJSON_GetObjectItem(g_cJSON_p4, "hosts");
    cJSON *keys = (tmp = cJSON_GetObjectItem(g_cJSON_p4, "keys"));
    for(i=0; i<cJSON_GetArraySize(hosts); i++) {

        strncpy(indi_str, cJSON_GetArrayItem(hosts, i)->valuestring, sizeof(key_str));
        inet_aton(indi_str, &indi_res);
        if (indi_res.s_addr == indi) {
            strncpy(key_str, cJSON_GetArrayItem(keys, i)->valuestring, sizeof(key_str));
            break;
        }
    }
    strncpy(res, key_str, sizeof(key_str));
    return 0;
}

uint32_t get_key_by_indi(uint32_t indi)
{
    int ret = 0;
    unsigned char res[64] = {0};
    ret = get_keystr_by_indi(indi, res);
    if (ret) {
        printf("get key by inid failed.\n");
        return 0;
    }

    return atoi(res);
}

int get_indi(struct in_addr *indi_res, int mask)
{
    cJSON *hosts = NULL;
    cJSON *tmp = NULL;
    int i, j;
    char *indi = (tmp = cJSON_GetObjectItem(g_cJSON_p4, "indicatel")) ? tmp->valuestring : NULL;
    char indi_str[64] = "10.0.3.1";

    hosts = cJSON_GetObjectItem(g_cJSON_p4, "hosts");
    if((indi == NULL) || (*indi == '\0')) {
        if(hosts != NULL) {
            j = 10*cJSON_GetArraySize(hosts);
            while(j--) {
                i = rand()%cJSON_GetArraySize(hosts);
                printf("i is %d.\n", i);
                if(((1<<i) & mask) != 0) {
                    continue;
                }
                strncpy(indi_str, cJSON_GetArrayItem(hosts, i)->valuestring, 32);
                break;
            }
        }
        //        strcpy(indi, hosts[i])
    } else {
        strncpy(indi_str, indi, sizeof(indi_str));
    }

    inet_aton(indi_str, indi_res);
    return 0;
}

int reverse_uint32(uint32_t *src)
{
    uint32_t tmp = 0;
    tmp = *src >> 24 | (*src >> 8) & 0xff00 | (*src << 8) & 0xff0000 | (*src << 24) & 0xff000000;
    *src = tmp;
    return 0;
}

int p4_header(int tc, char *p4_data, int *p4_len)
{
    int ret = 0;
    int offset=0;
    int i = 0;
    char lastip[8] = {0};
    char nextip[8] = {0};
    uint32_t pvf[4] = {0};
    int ts = 0;
    char opv[5][16] = {0};
    char opvd[16] = {0};
    int len = 0;
    uint32_t crc32_data = 0;
    cJSON *tmp = NULL;

    char *type = (tmp = cJSON_GetObjectItem(g_cJSON_p4, "p4_type")) ? tmp->valuestring : "epv";
    char *sdkey = (tmp = cJSON_GetObjectItem(g_cJSON_p4, "sdkey")) ? tmp->valuestring : "1234";

    struct in6_addr  ipv6_src = {0};
    inet_pton(AF_INET6, g_scanner_sip6, &ipv6_src);
    struct in6_addr  ipv6_dst = {0};
    inet_pton(AF_INET6, g_scanner_dip6, &ipv6_dst);

    unsigned char sid[32] = {0};
    ret = gen_sid(g_scanner_sip6, g_scanner_dip6, sdkey, sid);
    if (ret < 0) {
        //TODO
    }

    int hlim = (tmp = cJSON_GetObjectItem(g_cJSON_ipv6, "hlim")) ? tmp->valueint : 6;
    int mask = (tmp = cJSON_GetObjectItem(g_cJSON_p4, "mask")) ? tmp->valueint : 0;
    unsigned char datahash[16] = {0};
    ret = gen_datahash(sid, (char)hlim, g_payload, datahash);
    char MAC[8] = {0};
    ret = gen_mac(datahash, "", MAC);
    struct in_addr indi;

    char *key_str[32] = {NULL};
    uint32_t key[10] = {0};
    cJSON *keys = (tmp = cJSON_GetObjectItem(g_cJSON_p4, "keys"));
    len = cJSON_GetArraySize(keys);
    for (i=0; i<len; i++) {
        key_str[i] = (tmp = cJSON_GetArrayItem(keys, i)) ? tmp->valuestring : "0";
        key[i] = atoi(key_str[i]);
        printf("key %d is %x.\n", i, key[i]);
    }


    if (!strcmp(type, "epv")) {
        if(tc == 12){
            ret = get_indi(&indi, mask);
        } else {
            ret = get_indi(&indi, 0);
        }

       // memcpy(p4_data+offset, &(indi.s_addr), 4); offset += 4;
        memcpy(p4_data+offset, &(indi.s_addr), 4); offset += 4;
        memcpy(p4_data, datahash, 3);
        memcpy(p4_data+offset, datahash+4, 12); offset += 12;
        memcpy(p4_data+offset, sid, 16); offset += 16;
        memcpy(p4_data+offset, lastip, 4); offset += 4;
        memcpy(p4_data+offset, nextip, 4); offset += 4;
        memcpy(p4_data+offset, MAC, 8); offset += 8;
      //  if( tc == 199)
        //       memcpy(p4_data+offset,0,8);offset += 8;

    } else if (!strcmp(type, "opt")) {
//        memcpy(p4_data+offset, &indi.s_addr, 4); offset += 4;
        memcpy(p4_data+offset, datahash, 16); offset += 16;
        memcpy(p4_data+offset, sid, 16); offset += 16;

        crc32_data = *((uint32_t *)&ipv6_src + 3) + *((uint32_t *)&ipv6_dst + 3) + *((uint32_t *)datahash+3);
        reverse_uint32(&crc32_data);
        pvf[3] = crc32_run(0, (char *)&crc32_data, 4);
        memcpy(p4_data+offset, pvf, 16); offset += 16;
        memcpy(p4_data+offset, (char *)&ts, 4); offset += 4;
        for(i=0; i<5; i++) {
            ret = strmd5digest(key_str[i], opv[i]);
            if (ret < 0) {
                //TODO
            }

            memcpy(p4_data+offset, opv[i], 16); offset += 16;
        }

        for (i=0; i<16; i++) {
            opvd[i] = datahash[i] ^ datahash[(i+2)%16];
        }
        memcpy(p4_data+offset, opvd, 16); offset += 16;
    } else if (!strcmp(type, "rfl")) {
#if 1
        memset(p4_data+offset, 0, 4); offset += 4;
        memcpy(p4_data+offset, datahash+4, 12); offset += 12;
//        struct in6_addr  ipv6_dst = {0};
//        inet_pton(AF_INET6, g_scanner_dip6, &ipv6_dst);
        uint32_t sid[32] = {0};
        int sid_len = len;
//       if(tc == 22) {
//           sid_len -= 1;
//       }

        for(i=0; i<sid_len; i++) {
            if ((tc == 22) && (i == 2)) continue;
            if(key[i] != 0){
//                data = (uint64_t)datahash+atoll(key[i])+(uint64_t)ipv6_src+(uint64_t)ipv6_dst;
                crc32_data = key[i] + *((uint32_t *)&ipv6_src+3);
                reverse_uint32(&crc32_data);
                printf("key is %x ipv6_src is %x, res is %x.\n", key[i], *((uint32_t *)&ipv6_src+3), crc32_data);
                sid[i] = crc32_run(0, (char *)&crc32_data, 4);
                reverse_uint32(sid+i);
                memcpy(p4_data+offset, sid+i, 4); offset += 4;
            }
        }
#endif
#if 0
        char dhash[] = {0x00, 0x00, 0x00, 0x00, 0x7f, 0x03, 0x44, 0xfe, 0x4e, 0x87, 0x1a, 0x4c, 0x89, 0x6a, 0x4e, 0xbe};
//        int sid1 = 0x547b3691;
        int sid1 = 0x547b3692;
        int sid2 = 0xf4359add;
        int sid3 = 0x2a742459;
        int sid4 = 0x8035267e;
        int sid5 = 0xd908f7d5;
        memcpy(p4_data+offset, dhash, 16); offset += 16;
        memcpy(p4_data+offset, (char *)&sid1, 4); offset += 4;
        memcpy(p4_data+offset, (char *)&sid2, 4); offset += 4;
        memcpy(p4_data+offset, (char *)&sid3, 4); offset += 4;
        memcpy(p4_data+offset, (char *)&sid4, 4); offset += 4;
        memcpy(p4_data+offset, (char *)&sid5, 4); offset += 4;
#endif
        memcpy(p4_data+offset, nextip, 4); offset += 4;
        memcpy(p4_data+offset, MAC, 8); offset += 8;
    }

    *p4_len = offset;
    return 0;
}

int gen_p4_pkt(char *ifname, unsigned char *p4_pkt, unsigned int *p4_len)
{
    int ret = -1;
    int len  = 0;
    cJSON *tmp = NULL;
    uint8_t *ptmp = NULL;
    memset(p4_pkt, 0, *p4_len);

    uint16_t proto_3 = 0;

//eth
    char *smac = (tmp = cJSON_GetObjectItem(g_cJSON_eth, "smac")) ? tmp->valuestring : NULL;
    char *dmac = (tmp = cJSON_GetObjectItem(g_cJSON_eth, "dmac")) ? tmp->valuestring : "ff:ff:ff:ff:ff:ff";
    char *eth_type = (tmp = cJSON_GetObjectItem(g_cJSON_eth, "type")) ? tmp->valuestring : "86dd";

    ptmp = p4_pkt;
    char eth_type_hex[8];
    str2hex(eth_type, eth_type_hex);

    unsigned char data_eth[32] = {0};
    proto_3 = (eth_type_hex[0]<<8) | (eth_type_hex[1] & 0xff);


    ret = pkt6_eth(ifname, smac, dmac, proto_3, data_eth);

    printf("eth smac is %s dmac is %s type is %s.\n", smac, dmac, eth_type);
//ip data
    char *sip6 = (tmp = cJSON_GetObjectItem(g_cJSON_ipv6, "ip6_src")) ? tmp->valuestring : NULL;
    if((sip6 == NULL) || (*sip6 == '\0')) {
        get_ipv6_by_ifname(ifname, g_scanner_sip6);
    } else {
        strncpy(g_scanner_sip6, sip6, sizeof(g_scanner_sip6));
    }

    char *dip6 = (tmp = cJSON_GetObjectItem(g_cJSON_ipv6, "ip6_dst")) ? tmp->valuestring : " FF02:0:0:0:0:0:0:1";
    strncpy(g_scanner_dip6, dip6, sizeof(g_scanner_dip6));

    int nheader = (tmp = cJSON_GetObjectItem(g_cJSON_ipv6, "nheader")) ? tmp->valueint : 143;
    int tc = (tmp = cJSON_GetObjectItem(g_cJSON_ipv6, "tc")) ? tmp->valueint : 0;
    int hlim = (tmp = cJSON_GetObjectItem(g_cJSON_ipv6, "hlim")) ? tmp->valueint : 6;
    if (hlim == 0) {
        hlim = 6;
    }

    if (nheader == 0) {
        nheader = 143;
    }

    //p4

    char p4_data[256] = {0};
    int p4_header_len = sizeof(p4_data);
    ret = p4_header(tc, p4_data, &p4_header_len);

//ip
    struct ip6_hdr iphdr;
    ret = pkt6_ip(ifname, sip6, dip6, (short)nheader ? nheader : 143, (char)hlim ? hlim : 6, tc, (char *)&iphdr, strlen(g_payload)+p4_header_len);

//udp
    int sport = (tmp = cJSON_GetObjectItem(g_cJSON_udp, "port_src")) ? tmp->valueint : 8888;
    int dport = (tmp = cJSON_GetObjectItem(g_cJSON_udp, "port_dst")) ? tmp->valueint : 6666;
    struct udphdr udphdr;
    pkt6_udp(sport ? sport : 8888, dport ? dport : 6666, (char *)&udphdr, g_payload, strlen(g_payload), iphdr);


    memcpy(ptmp, data_eth, ETH_HDRLEN);        ptmp += ETH_HDRLEN;
    ret = print_pkt(p4_pkt, ptmp);

    memcpy(ptmp, &iphdr, IP6_HDRLEN);    ptmp += IP6_HDRLEN;
    ret += print_pkt(p4_pkt+ret, ptmp);

    memcpy(ptmp, p4_data, p4_header_len);  ptmp += p4_header_len;
    ret = print_pkt(p4_pkt+ret, ptmp);

    memcpy(ptmp, &udphdr, UDP_HDRLEN);   ptmp += UDP_HDRLEN;
//    ret = print_pkt(p4_pkt+ret, ptmp);

    memcpy(ptmp, g_payload, strlen(g_payload)); ptmp += strlen(g_payload);
//    ret = print_pkt(p4_pkt, ptmp);
    *p4_len = (char *)ptmp+ret - (char *)p4_pkt;

    return 0;
}

