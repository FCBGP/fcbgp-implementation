/********************************************************************************
 * File Name:    client.c
 * Author:       basilguo@163.com
 * Version:      0.0.1
 * Created Time: 2024-05-10 09:30:32
 * Description:  This client will mock the BGPd to send BM to FCServer.
 *******************************************************************************/

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

#define MAX_SIZE 2048

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

void help()
{
    printf("USAGE: bin/client <ip-address> <msg>\n");
    printf("\t<ip-address>: client ipv6 address\n");
    printf("\t<msg>:        1 for pubkey (not support now)\n");
    printf("\t              2 for bm bgpd=>fcs\n");
    printf("\t              3 for bm fcs=>fcs\n");
    printf("\t              4 for bgp router topo link\n");
    exit(EXIT_FAILURE);
}

int prepare_msg_bm(char *msg, int msg_type)
{
    int len = 0, length = 0, lengthpos = 0;
    u8 u8v = 0;
    u16 u16v = 0;
    u32 u32v = 0;

    // u8 version
    u8v = 1;
    memcpy(msg + len, &u8v, sizeof(u8));
    len += sizeof(u8);
    // u8 type
    u8v = msg_type; // bm from bgpd or fcs
    memcpy(msg + len, &u8v, sizeof(u8));
    len += sizeof(u8);
    // u16 length
    lengthpos = len;
    u16v = 0;
    len += sizeof(u16);
    // u8 ipversion
    u8v = 4;
    memcpy(msg + len, &u8v, sizeof(u8));
    len += sizeof(u8);
    // u8 type
    u8v = 0;
    memcpy(msg + len, &u8v, sizeof(u8));
    len += sizeof(u8);
    // u8 action
    u8v = 0;
    memcpy(msg + len, &u8v, sizeof(u8));
    len += sizeof(u8);
    // u8 fc_num
    u8v = 1;
    memcpy(msg + len, &u8v, sizeof(u8));
    len += sizeof(u8);
    // u8 src_ip_num
    u8v = 1;
    memcpy(msg + len, &u8v, sizeof(u8));
    len += sizeof(u8);
    // u8 dst_ip_num
    u8v = 1;
    memcpy(msg + len, &u8v, sizeof(u8));
    len += sizeof(u8);
    // u16 siglen
    u16v = htons(72);
    memcpy(msg + len, &u16v, sizeof(u16));
    len += sizeof(u16);
    // u32 local_asn
    u32v = htonl(10);
    memcpy(msg + len, &u32v, sizeof(u32));
    len += sizeof(u32);
    // u32 version
    u32v = 0;
    memcpy(msg + len, &u32v, sizeof(u32));
    len += sizeof(u32);
    // u32 subversion
    u32v = 0;
    memcpy(msg + len, &u32v, sizeof(u32));
    len += sizeof(u32);
    // FC_ip_t src_ip[]
    u32v = htonl(0x0a0b0c0d);
    memcpy(msg + len, &u32v, sizeof(u32));
    len += sizeof(u32);
    u8v = 24;
    memcpy(msg + len, &u8v, sizeof(u8));
    len += sizeof(u8);
    // FC_ip_t dst_ip[]
    u32v = htonl(0x01020304);
    memcpy(msg + len, &u32v, sizeof(u32));
    len += sizeof(u32);
    u8v = 24;
    memcpy(msg + len, &u8v, sizeof(u8));
    len += sizeof(u8);
#if 0
    // il num
    u8v = 1;
    memcpy(msg+len, &u8v, sizeof(u8));
    len += sizeof(u8);
    // interface list
    for (int ii = 0; ii < 1; ++ii)
    {
        u32v = htonl(0x01010101);
        memcpy(msg+len, &u32v, sizeof(u32));
        len += sizeof(u32);
    }
#endif
    // FC_t fclist[1], fi: fc index
    for (int fi = 0; fi < 1; ++fi)
    {
        // pasn
        u32v = htonl(20);
        memcpy(msg + len, &u32v, sizeof(u32));
        len += sizeof(u32);
        // casn
        u32v = htonl(10);
        memcpy(msg + len, &u32v, sizeof(u32));
        len += sizeof(u32);
        // nasn
        u32v = htonl(30);
        memcpy(msg + len, &u32v, sizeof(u32));
        len += sizeof(u32);
        // u8 ski[20]
        for (int i = 0; i < 20; ++i)
        {
            u8v = 0;
            memcpy(msg + len, &u8v, sizeof(u8));
            len += sizeof(u8);
        }
        // u8 algo_id
        u8v = 1;
        memcpy(msg + len, &u8v, sizeof(u8));
        len += sizeof(u8);
        // u8 flags
        u8v = 0;
        memcpy(msg + len, &u8v, sizeof(u8));
        len += sizeof(u8);
        // u16 siglen
        u16v = htons(72);
        memcpy(msg + len, &u16v, sizeof(u16));
        len += sizeof(u16);
        // u8 signature[80]
        for (int i = 0; i < 72; ++i)
        {
            u8v = i;
            memcpy(msg + len, &u8v, sizeof(u8));
            len += sizeof(u8);
        }
    }
    // u8 ski[20]
    for (int i = 0; i < 20; ++i)
    {
        u8v = 0;
        memcpy(msg + len, &u8v, sizeof(u8));
        len += sizeof(u8);
    }
    // u8 signature[80]
    for (int i = 0; i < 72; ++i)
    {
        u8v = i;
        memcpy(msg + len, &u8v, sizeof(u8));
        len += sizeof(u8);
    }

    // length
    length = htons(len);
    memcpy(msg + lengthpos, &length, sizeof(u16));

    return len;
}

int prepare_msg_topo(char *msg, u8 msg_type,
                     u8 action, bool del_all_neighbor, bool del_all_il)
{
    int len = 0, length = 0, lengthpos = 0;
    u8 u8v = 0;
    u32 u32v = 0;

    // u8 version
    u8v = 1;
    memcpy(msg + len, &u8v, sizeof(u8));
    len += sizeof(u8);
    // u8 type
    u8v = msg_type; // bm from bgpd or fcs
    memcpy(msg + len, &u8v, sizeof(u8));
    len += sizeof(u8);
    // u16 length
    lengthpos = len;
    len += sizeof(u16);
    // action
    memcpy(msg + len, &action, sizeof(u8));
    len += sizeof(u8);
    // reserved;
    u8v = 0;
    memcpy(msg + len, &u8v, sizeof(u8) * 3);
    len += 3 * sizeof(u8);
    // bgpid
    u32v = htonl(0xc0a80a01);
    memcpy(msg + len, &u32v, sizeof(u32));
    len += sizeof(u32);
    // local-asn
    u32v = htonl(10);
    memcpy(msg + len, &u32v, sizeof(u32));
    len += sizeof(u32);

    // neighbor_num;
    if (action == 1 && del_all_neighbor)
    {
        u32v = htonl(0xffffffff);
    }
    else
    {
        u32v = htonl(3);
    }
    memcpy(msg + len, &u32v, sizeof(u32));
    len += sizeof(u32);

    // neighbors
    if (action == 0 || !del_all_neighbor)
    {
        // neighbor-asn
        u32v = htonl(20);
        memcpy(msg + len, &u32v, sizeof(u32));
        len += sizeof(u32);
        // il-num
        u32v = htonl(1);
        memcpy(msg + len, &u32v, sizeof(u32));
        len += sizeof(u32);
        // iface-list
        u32v = htonl(0x10000001);
        memcpy(msg + len, &u32v, sizeof(u32));
        len += sizeof(u32);
        // neighbor-asn
        u32v = htonl(30);
        memcpy(msg + len, &u32v, sizeof(u32));
        len += sizeof(u32);
        // il-num
        if (del_all_il)
        {
            u32v = htonl(0x0);
            memcpy(msg + len, &u32v, sizeof(u32));
            len += sizeof(u32);
        }
        else
        {
            u32v = htonl(2);
            memcpy(msg + len, &u32v, sizeof(u32));
            len += sizeof(u32);
            // iface-list
            u32v = htonl(0x10000002);
            memcpy(msg + len, &u32v, sizeof(u32));
            len += sizeof(u32);
            u32v = htonl(0x10000003);
            memcpy(msg + len, &u32v, sizeof(u32));
            len += sizeof(u32);
            // neighbor-asn
            u32v = htonl(40);
            memcpy(msg + len, &u32v, sizeof(u32));
            len += sizeof(u32);
            // il-num
            u32v = htonl(1);
            memcpy(msg + len, &u32v, sizeof(u32));
            len += sizeof(u32);
            // iface-list
            u32v = htonl(0x10000004);
            memcpy(msg + len, &u32v, sizeof(u32));
            len += sizeof(u32);
        }
    }

    // length
    length = htons(len);
    memcpy(msg + lengthpos, &length, sizeof(u16));

    return len;
}

int prepare_msg_for_type4(char *msg)
{
    int len = 0;
    char choice = 0;

    while (choice == 0)
    {
        printf("\n");
        printf("\t1: add topo information(20-10, 30=10, 40-10)\n");
        printf("\t2: del topo information(20-10, 30=10, 40-10)\n");
        printf("\t3: del topo information(30=10), il-num = 0x0\n");
        printf("\t4: del all topo information, neighbor-num = 0xffffffff\n");
        printf("Enter your choice (1,2,3,4, q): ");
        scanf("%c", &choice);
        switch (choice)
        {
        case '1':
            len = prepare_msg_topo(msg, 4, 0, /* add/update */
                                   0 /* del_all_neighbor */, 0 /* del_all_il */);
            break;
        case '2':
            len = prepare_msg_topo(msg, 4, 1, /* add/update */
                                   0 /* del_all_neighbor */, 0 /* del_all_il */);
            break;
        case '3':
            len = prepare_msg_topo(msg, 4, 1, /* add/update */
                                   0 /* del_all_neighbor */, 1 /* del_all_il */);
            break;
        case '4':
            len = prepare_msg_topo(msg, 4, 1, /* add/update */
                                   1 /* del_all_neighbor */, 1 /* del_all_il */);
            break;
        case 'q':
            exit(EXIT_SUCCESS);
        default:
            printf("\nERROR: no such choice: %d\n", choice);
            choice = 0;
            break;
        }
    }

    return len;
}

int prepare_msg(char *msg, u8 msg_type)
{
    int len = 0;

    switch (msg_type)
    {
    case 1: // pubkey
        printf("pubkey msg is not supported\n");
        len = -1;
        break;
    case 2: // bm from bgpd
    case 3: // bm from fcs
        len = prepare_msg_bm(msg, msg_type);
        break;
    case 4: // router link topo info
        len = prepare_msg_for_type4(msg);
        break;
    default:
        printf("msg_type: %d is not supported\n", msg_type);
        len = -1;
        break;
    }

    return len;
}

int main(int argc, char *argv[])
{
    int count = 1, sockfd = 0;
    int msglen = 0, ret = 0;
    u8 msg_type = 0;
    struct sockaddr_in6 sockaddr, clisockaddr;
    char msg[MAX_SIZE] = {0};

    if (argc != 3)
    {
        help();
    }

    msg_type = atoi(argv[2]);

    clisockaddr.sin6_family = AF_INET6;
    clisockaddr.sin6_port = htons(0);
    inet_pton(AF_INET6, argv[1], &clisockaddr.sin6_addr);

    sockaddr.sin6_family = AF_INET6;
    sockaddr.sin6_port = htons(23162);
    inet_pton(AF_INET6, "::1", &sockaddr.sin6_addr);

    sockfd = socket(AF_INET6, SOCK_STREAM, 0);
    if (sockfd < 0)
    {
        perror("socket()");
        exit(EXIT_FAILURE);
    }

    int yes = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));

    if (bind(sockfd, (struct sockaddr *)&clisockaddr, sizeof(clisockaddr)) < 0)
    {
        perror("bind()");
        exit(EXIT_FAILURE);
    }

    if (connect(sockfd, (struct sockaddr *)&sockaddr, sizeof(sockaddr)) < 0)
    {
        perror("connect()");
        exit(EXIT_FAILURE);
    }

    while (1)
    {
        printf("Press enter key to send one BM message: ");

        msglen = prepare_msg(msg, msg_type);
        printf("msg_type: %d, msg_len: %d\n", msg_type, msglen);
        if (msglen < 0)
        {
            exit(EXIT_FAILURE);
        }

        if ('q' == getchar())
            break;

        ret = send(sockfd, msg, msglen, 0);
        printf("msglen: %d, ret: %d\n", msglen, ret);

        printf("The %d time to send\n\n", count);
        count++;
    }

    return 0;
}
