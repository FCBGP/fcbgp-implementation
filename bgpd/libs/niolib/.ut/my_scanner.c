#include <stdio.h>
#include <string.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <linux/if_ether.h>
#include <time.h>

#define USE_MYSQL 0

#if USE_MYSQL
#include <mysql/mysql.h>
#endif

#include "libnio.h"
#include "libdiag.h"
#include "libcrc32.h"
#include "libsysmgr.h"
#include "libmutex.h"
#include "libcondition.h"
#include "libhead.h"
#include "libdhcpv6.h"

#define NIO_SCANNER_LENGTH 2500
#define PROTO_IP 0x0800
#define PROTO_arp 0x0806                    //current not used
#define PROTO_IPV6 0x86dd                 // current not used

#define MYSQL_IP "localhost"
#define MYSQL_USER "nidtga"
#define MYSQL_PASS "NIDTGA_802.1x"
#define MYSQL_DATABASE "campus6"
#define MYSQL_PORT 3306

#define LINK_ADDR "fe80::47af:af74:df5f:5a95"
#define LOCAL_IPV6 "2402:f000:6:1c02:1::200"
#define REMOTE_IPV6 "2402:f000:6:1c02:1::100"

nio_ctx_t *g_scanner_nio = NULL;

static uint8_t g_scanner_smac[6] = {0, };
static uint8_t g_scanner_dmac[6] = {0xcc,0xb0,0xda,0xa5,0x2c,0xF5};

unsigned short my_checksum(unsigned char *addr, int len){
    int nleft=len;
    int sum=0;
    unsigned char * w=addr;
    unsigned short answer=0;

    while (nleft>1)
    {
        sum+=*w << 8 | *(w+1);
        w += 2;
        nleft-=2;
    }

    if (nleft==1)
    {
        *(unsigned char *)(&answer)=*(unsigned char *)w;
        sum+=answer;
    }

    sum=(sum>>16)+(sum & 0xffff);
    sum+=(sum>>16);
    answer=~sum;
    return(answer);
}

int reply_process(nio_pkt_t *pkt)
{

    return 0;
}

int relay_reply_process(nio_pkt_t *pkt)
{

    return 0;
}

int scanner_process_ipv6(nio_ctx_t *ctx, nio_pkt_t * pkt)
{
    printf("recv ipv6 pkt.\n");
    int ret;
    int proto_4 = pkt->data[20];

    char *req_msg = NULL;
    req_msg = malloc(1024);
    if (req_msg == NULL) {
        return -ENOMEM;
    }

    if (proto_4 == 17) {
        unsigned short sport = pkt->data[54]<<8 |  pkt->data[55];
        unsigned short dport = pkt->data[56]<<8 |  pkt->data[57];;
        if (sport == 547 && dport == 546) {
            unsigned char msg_type = pkt->data[62];
            switch (msg_type) {
            case 0x02:
                ret = request(pkt, req_msg);

                nio_pkt_t req_pkt;
                memset (&req_pkt, 0, sizeof(nio_pkt_t));

                req_pkt.data = (uint8_t *)req_msg;
                req_pkt.length = ret;

                ret = nio_forward(g_scanner_nio, 0, &req_pkt);
                if (ret < 0) {
                    free(req_msg);
                    DIAG_ERROR("send hex failed.\n");
                    return -1;
                }
                break;

            case 0x07:
                ret = reply_process(pkt);
                break;
            }
        } else if(sport == 547 && dport == 547) {
            char *relay_req_msg = NULL;

            relay_req_msg = malloc(1024);
            if (relay_req_msg == NULL) {
                return -ENOMEM;
            }

            unsigned char msg_type = pkt->data[62];
            if (msg_type != 0x0d) {
                DIAG_ERROR("not a reply pkt.\n");
                return -1;
            }

            unsigned char msg_type_dhcp = pkt->data[100];
            switch (msg_type_dhcp) {
            case 0x02:
                ret = relay_request(pkt, req_msg);

                nio_pkt_t req_pkt;
                memset (&req_pkt, 0, sizeof(nio_pkt_t));

                req_pkt.data = (uint8_t *)req_msg;
                req_pkt.length = ret;

                ret = nio_forward(g_scanner_nio, 0, &req_pkt);
                if (ret < 0) {
                    free(req_msg);
                    DIAG_ERROR("send hex failed.\n");
                    return -1;
                }
                break;
            case 0x07:
                ret = relay_reply_process(pkt);
            }

        }
    }
    free(req_msg);
    return 0;
}

int scanner_link_init(char *ifname)
{
    int ret;

    if (ifname == NULL) {
        DIAG_ERROR("invalid if name!\n");
        return -EINVAL;
    }

    if (g_scanner_nio!= NULL) {
        DIAG_ERROR("cfg nio exists!\n");
        return -EINVAL;
    }

    ret = sys_netif_ethaddr_get(ifname, g_scanner_smac);
    if (ret < 0) {
        DIAG_ERROR("get scanner interface %s ethaddr failed\n", ifname);
        return ret;
    }

    g_scanner_nio = nio_create(ifname, g_scanner_smac, g_scanner_dmac, &g_raw_sock_ops);
    if (g_scanner_nio == NULL) {
        DIAG_ERROR("create scanner nio failed\n");
        return -ENOMEM;
    }

    int argc = 8;
    int proto = ETH_P_ALL;

    int argv[] = {proto, 2, 0x400000, 0x400000, 3000, 1, 0, 0};
    ret = nio_open(g_scanner_nio, argc, argv);
    if (ret < 0) {
        DIAG_ERROR("open scanner nio failed\n");
        nio_close(g_scanner_nio);
        g_scanner_nio = NULL;
        return ret;
    }

    ret = nio_add_ptype(g_scanner_nio, 0x86dd, scanner_process_ipv6);
    if (ret < 0) {
        DIAG_ERROR("add scanner nio handler failed\n");
        nio_close(g_scanner_nio);
        g_scanner_nio = NULL;
        return ret;
    }

    ret = nio_start(g_scanner_nio);
    if (ret < 0) {
        DIAG_ERROR("start scanner nio failed\n");
        nio_close(g_scanner_nio);
        g_scanner_nio = NULL;
        return ret;
    }

    return 0;
}

int scanner_link_fini(void)
{
    if (g_scanner_nio) {
        nio_stop(g_scanner_nio);
        nio_close(g_scanner_nio);
        g_scanner_nio = NULL;
    }
    return 0;
}

int get_local_ip(const char *eth_inf, char *ip)
{
    int sd;
    struct sockaddr_in sin;
    struct ifreq ifr;

    sd = socket(AF_INET, SOCK_DGRAM, 0);
    if (-1 == sd)
    {
        printf("socket error: %s\n", strerror(errno));
        return -1;
    }

    strncpy(ifr.ifr_name, eth_inf, IFNAMSIZ);
    ifr.ifr_name[IFNAMSIZ - 1] = 0;

    // if error: No such device
    if (ioctl(sd, SIOCGIFADDR, &ifr) < 0)
    {
        printf("ioctl error: %s\n", strerror(errno));
        close(sd);
        return -1;
    }

    memcpy(&sin, &ifr.ifr_addr, sizeof(sin));
    snprintf(ip, 32, "%s", inet_ntoa(sin.sin_addr));

    close(sd);
    return 0;
}

static int myscanner_send_tcp_syn(char *sour_ip, char *dest_ip, int port)
{
    int ret;
    char tmp[NIO_SCANNER_LENGTH + 8] = {0, };
    char buffer[NIO_SCANNER_LENGTH + 8] = {0, };
    IP_HEADER *ip = NULL;
    struct _tcphdr tcpHeader ;
    struct psd_hdr psdHeader ;

    tcpHeader.th_dport = htons(port) ;
    //源端口
    tcpHeader.th_sport = htons(60000) ;
    //序列号？？
    tcpHeader.th_seq = htonl(0x1245678);
    //确认号
    tcpHeader.th_ack = 0;
    //（4位首部长度/4位保留字）
    tcpHeader.th_lenres = (sizeof(tcpHeader) / 4 << 4 | 0);
    //SYN标志
    tcpHeader.th_flag = SYN;//SYN
    //滑动窗口
    tcpHeader.th_win = htons(65535) ;
    //16位紧急数据偏移量
    tcpHeader.th_urp = 0;
    //16位校验和
    tcpHeader.th_sum = 0;
    //psdheader

    ip = (IP_HEADER *)buffer;
    ip->h_lenver = 0x45;
    ip->tos = 0;
    ip->total_len = htons(sizeof(IP_HEADER) + sizeof(tcpHeader));
    ip->ident = htons(0);
    ip->frag_and_flags = htons(0x02 << 13);
    ip->ttl = 64;
    ip->proto = 6;
    ip->checksum = 0;
    ip->destIP = inet_addr(dest_ip);
    ip->sourceIP = inet_addr(sour_ip);
    ip->checksum = htons(my_checksum((unsigned char *)ip, sizeof(IP_HEADER)));

    psdHeader.saddr = inet_addr(sour_ip);
    psdHeader.daddr = inet_addr(dest_ip);
    psdHeader.mbz = 0;  // mbz = must be zero, 用于填充对齐
    psdHeader.ptcl = ip->proto;  //8位协议号
    psdHeader.tcpl = htons(sizeof(tcpHeader)) ;

    //set checksum 使用伪头计算TCP校验和
    memcpy(tmp ,&psdHeader,sizeof(psdHeader)) ;
    memcpy(tmp + sizeof(psdHeader),&tcpHeader,sizeof(tcpHeader)) ;
    tcpHeader.th_sum = htons(my_checksum((unsigned char*)tmp, sizeof(psdHeader)+sizeof(tcpHeader))) ;

    //最终的组包（TCP+IP）
    memcpy(buffer+sizeof(IP_HEADER), &tcpHeader, sizeof(tcpHeader)) ;

    ret = nio_send(g_scanner_nio, PROTO_IP, (uint8_t *)buffer, sizeof(IP_HEADER) + sizeof(tcpHeader));
    if (ret < 0) {
        DIAG_ERROR("send request packet failed.\n");
        return ret;
    }

    return ret;
}


char char_to_hex(char c)
{
    char ret;
    if (c >= '0' && c <= '9') {
        ret = c - '0';
    } else if (c >= 'a' && c <= 'f') {
        ret = c-'a'+10;
    } else if (c >= 'A' && c <= 'F') {
        ret = c-'A'+10;
    } else {
        ret = -1;
    }

    return ret;
}

int myscanner_send_hex(char *hex)
{
    int ret;
    int i;
    nio_pkt_t pkt;
    memset (&pkt, 0, sizeof(nio_pkt_t));

    char *buffer = NULL;
    buffer = malloc(NIO_SCANNER_LENGTH + 8);
    if (buffer == NULL) {
        return -ENOMEM;
    }
    memset(buffer, 0, NIO_SCANNER_LENGTH + 8);

    pkt.data = (uint8_t *)buffer;
    for (i=0; i<strlen(hex); i+=2) {
        *(buffer++) = char_to_hex(hex[i]) << 4 | char_to_hex(hex[i+1]);
        pkt.length++;
    }

    ret = nio_forward(g_scanner_nio, 0, &pkt);
    if (ret < 0) {
        DIAG_ERROR("send hex failed.\n");
        return ret;
    }

    buffer = NULL;   //we should not use free, because it is freed in nio_forward function
    return 0;
}

int str2hex(char *str, char *hex)
{
    int i = 0;
    char c;
    char *pchar;
    char tmp[32] = {0, };

    pchar = tmp;
    for (i=0; i<strlen(str); i++) {
        c = str[i];
        if (c == ':') {
            continue;
        } else if(((c >= '0') && (c <= '9')) || ((c >= 'a') && (c <= 'f')) || ((c >= 'A') && (c <= 'F'))) {
            *pchar++ = c;
        } else {
            printf("INPUT WRONG!!!.\n");
            return -1;
        }
    }

    pchar = hex;
    for(i=0; i<sizeof(tmp); i+=2) {
        c = tmp[i];
        if ((c >= '0') && (c <= '9')) {
            *pchar = (c - '0') << 4;
        } else if((c >= 'a') && (c <= 'f')) {
            *pchar = (c - 'a' + 10) << 4;
        } else if ((c >= 'A') && (c <= 'F')) {
            *pchar = (c - 'A' + 10) << 4;
        }

        c = tmp[i+1];
        if ((c >= '0') && (c <= '9')) {
            *pchar |= (c - '0');
        } else if((c >= 'a') && (c <= 'f')) {
            *pchar |= (c - 'a' + 10);
        } else if ((c >= 'A') && (c <= 'F')) {
            *pchar |= (c - 'A' + 10);
        }
        pchar++;
    }

    return 0;
}

#if USE_MYSQL
int mysql_postauth(char *username, char *mac)
{
    int ret;
    MYSQL *conn;
    char sql_cmd[1024] = {0, };

    memset (sql_cmd, 0, sizeof(sql_cmd));
    snprintf(sql_cmd, 1024, "insert into radpostauth(username, pass, reply, user_mac) values (%s, 0, 'Access-Accept', %s)", username, mac);

    conn = mysql_init(NULL);
    if (conn == NULL) {
        DIAG_ERROR("mysql_init failed.\n");
        return -1;
    }

    if (mysql_real_connect(conn, MYSQL_IP, MYSQL_USER, MYSQL_PASS, MYSQL_DATABASE, MYSQL_PORT, NULL, 0)) {
        DIAG_INFO("process mysql cmd %s.\n", sql_cmd);
        ret = mysql_query(conn, sql_cmd);
        return ret;
    } else {
        DIAG_ERROR("mysql connect failed.\n");
        mysql_close(conn);
    }

    return 0;
}
#endif

int main(int argc, char *argv[])
{
    int i;
    int ret = 0;
    int verbose = 0;
    char dipaddr[32] = {0, };
    char sipaddr[32] = {0, };
    int count = 0;
    int port = 6666;
    char *ifname = NULL;
    char *hex = NULL;
    char smac[32] = {0, };
    char dhcp_test = 0;
    char loop = 0;

     diag_init("test_dhcp");

    for (i=0; i<argc; i++) {
        if (strcmp(argv[i], "-i") == 0) {
            ifname = argv[i + 1];
        } else if (strcmp(argv[i], "-v") == 0) {
            verbose = 1;
        } else if (strcmp(argv[i], "-syn") == 0) {
            strncpy(dipaddr, argv[i+1], sizeof(dipaddr));
        } else if (strcmp(argv[i], "-p") == 0) {
            port = atoi(argv[i+1]);
        } else if (strcmp(argv[i], "-hex") == 0) {
            hex = argv[i+1];
        } else if (strcmp (argv[i], "-dhcp") == 0) {
            dhcp_test = 1;
            if (argv[i+1]) {
                count = atoi(argv[i+1]);
            } else {
                count = 3;
            }
        } else if (strcmp(argv[i], "loop") == 0) {
            loop = 1;
        }else if (strcmp(argv[i], "-h") == 0) {
            printf("%s -i <interface> { -syn <destip> | -hex <hexcode> | -dhcp <count> } -v | -h | -loop \n", argv[0]);
            return 0;
        }
    }

    if (ifname == NULL || !(strcmp(dipaddr, "") || hex != NULL || count != 0)) {
        DIAG_ERROR("(ip or hex) and ifname must be given.\n");
        printf("(ip or hex) and ifname must be given.\n");
        return -1;
    }

    ret = scanner_link_init(ifname);
    if (ret < 0) {
        DIAG_ERROR("scanner link %s init failed\n", ifname);
        return ret;
    }

    if (verbose) {
        nio_verbose(g_scanner_nio, 1);
    }

 //  ret = get_local_ip(ifname, sipaddr);
 //  {
 //      if (ret < 0) {
 //          DIAG_ERROR("get local address failed.\n");
 //          goto out;
 //      }
 //  }


    if (strcmp(dipaddr, "")) {
        ret = myscanner_send_tcp_syn(sipaddr, dipaddr, port);
        if (ret < 0) {
            DIAG_ERROR("send syn to %s:%d failed.\n", dipaddr, port);
            goto out;
        }
    }

    if (hex != NULL) {
        ret = myscanner_send_hex(hex);
        if (ret < 0) {
            DIAG_ERROR("send hex failed.\n");
            goto out;
        }
    }

    if (dhcp_test) {
        char *solicit_msg;
        char smac_hex[6] = {0, };
        char username[16] ={'8','0','0','0','0', };
        char *p = NULL;

        srand(clock());
       if (str2hex(smac, smac_hex) < 0) {
           DIAG_ERROR("input smac invoid.\n");
           return -1;
       }

       while(count-- || loop) {
           p = smac;
           for (i=0; i<6; i++) {
               sprintf(p++, "%x", rand() % 16);
               sprintf(p++, "%x", rand() % 16);
               if (i!= 5) {
                   *p++ = ':';
               }
           }

           p = username+5;
           for(i=0; i<5; i++) {
            sprintf(p++, "%x", rand() % 16);
           }


#if USE_MYSQL
           mysql_postauth(username, smac);
#endif

           if (str2hex(smac, smac_hex) < 0) {
               DIAG_ERROR("input smac invoid.\n");
                return -1;
            }

           solicit_msg = malloc(1024);
           if (solicit_msg == NULL) {
               return -ENOMEM;
           }
#if 1
           char client_mac[8] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x0};
           ret = relay_solicit(LOCAL_IPV6, REMOTE_IPV6, LINK_ADDR, client_mac, ifname, solicit_msg);
           if (ret < 0) {
                DIAG_ERROR("generate solicit relay pkt failed.\n");
                goto out;
           }
#endif

#if 0
           ret = solicit(smac_hex, ifname, solicit_msg, LINK_ADDR);
            if (ret < 0) {
                DIAG_ERROR("generate solicit pkt failed.\n");
                goto out;
            }
#endif
            nio_pkt_t pkt;
            memset (&pkt, 0, sizeof(nio_pkt_t));

            pkt.data = (uint8_t *)solicit_msg;
            pkt.length = ret;

            ret = nio_forward(g_scanner_nio, 0, &pkt);
            if (ret < 0) {
                DIAG_ERROR("send hex failed.\n");
                goto out;
            }
        }
    }

    while(1);
out:
    scanner_link_fini();
    nio_stop(g_scanner_nio);
    nio_close(g_scanner_nio);
    return ret;
}

