/********************************************************************************
* File Name:    test_send_fclist.c
* Author:       basilguo@163.com
* Created Time: 2023-10-09 08:35:05
* Description:
********************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <stdint.h>
#include <unistd.h>

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;

int main(int argc, char *argv[])
{
    char buff[BUFSIZ] = {0};
    int length = 0;
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in sockaddr;
    int len = 0, ret = 0;

    // hdr
    buff[length] = 2; // bm
    length += sizeof(u8);
    buff[length] = 0; // length
    length += sizeof(u16);
    buff[length] = 0; // reserved
    length += sizeof(u8);

    // bm
    buff[length] = 4; // ipversion
    length += sizeof(u8);
    buff[length] = 0; // type onpath
    length += sizeof(u8);
    buff[length] = 0; // action update
    length += sizeof(u8);
    buff[length] = 3; // fc-num
    length += sizeof(u8);
    buff[length] = 2; // src-ip-num
    length += sizeof(u8);
    buff[length] = 1; // dst-ip-num
    length += sizeof(u8);

    u16 siglen = 72; // siglen
    siglen = htons(siglen);
    memcpy(&buff[length], &siglen, sizeof(u16));
    length += sizeof(u16);

    u32 asn = htonl(10);
    memcpy(&buff[length], &asn, sizeof(u32)); // local_asn;
    length += sizeof(u32);
    buff[length] = 0; // version;
    length += sizeof(u32);
    buff[length] = 0; // subversion;
    length += sizeof(u32);

    asn = htonl(0xc0a80101);
    memcpy(&buff[length], &asn, sizeof(u32)); // src-ip
    length += sizeof(u32);
    buff[length] = 0x18;
    length += sizeof(u8);

    asn = htonl(0xc0a80201);
    memcpy(&buff[length], &asn, sizeof(u32)); // src-ip
    length += sizeof(u32);
    buff[length] = 0x18;
    length += sizeof(u8);

    asn = htonl(0xc0a80301);
    memcpy(&buff[length], &asn, sizeof(u32)); // dst-ip
    length += sizeof(u32);
    buff[length] = 0x18;
    length += sizeof(u8);

    // fclist -- 1
    for (int j=0; j<3; ++j)
    {
        asn = htonl(0 + j*10);
        memcpy(&buff[length], &asn, sizeof(u32)); // previous-asn
        length += sizeof(u32);
        asn = htonl(10 + j*10);
        memcpy(&buff[length], &asn, sizeof(u32)); // current-asn
        length += sizeof(u32);
        asn = htonl(20 + j*10);
        memcpy(&buff[length], &asn, sizeof(u32)); // nexthop-asn
        length += sizeof(u32);
        memset(&buff[length], 0, 20); // ski
        length += 20;
        buff[length] = 1; // algo-id
        length += sizeof(u8);
        buff[length] = 0; // flags
        length += sizeof(u8);

        siglen = htons(72); // siglen
        memcpy(&buff[length], &siglen, sizeof(u16));
        length += sizeof(u16);

        u32 sig1 = htonl(0x01234567); // fclist
        u32 sig2 = htonl(0x89abcdef);
        for (int i=0; i<9; ++i)
        {
            memcpy(&buff[length], &sig1, sizeof(sig1));
            length += sizeof(u32);
            memcpy(&buff[length], &sig2, sizeof(sig2));
            length += sizeof(u32);
        }
    }

    len = length;
    len= htons(len);
    memcpy(&buff[1], &len, sizeof(u16));



    sockaddr.sin_family = AF_INET;
    sockaddr.sin_port = htons(23160);
    inet_pton(AF_INET, "192.168.88.131", &sockaddr.sin_addr);

    ret = connect(sockfd, (struct sockaddr *)&sockaddr, sizeof(sockaddr));
    if (ret < 0)
    {
        fprintf(stderr, "connect() error\n");
        perror("connect()");
    }

    len = 0;

    while (len != length)
    {
        len = len + send(sockfd, buff+len, length-len, 0);
        printf("len = %d, total-length = %d\n", len, length);
    }

    close(sockfd);

    return 0;
}
