/********************************************************************************
* File Name:    main.c
* Author:       basilguo@163.com
* Created Time: 2023-09-27 07:55:18
* Description:
********************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <signal.h>
#include <time.h>
#include <assert.h>
#include <getopt.h>

#include "libdiag.h"
#include "libmutex.h"
#include "libncs.h"
#include "utils.h"

static void help()
{
    printf("\t-h                            print this message.\n");
    printf("\t-a                            specify local as number.\n");
    printf("\t-f <asnlist.json location>    specify the location of asnlist.json\n");
}

static int parse_args(int argc, char *argv[], fcserver_t *fcserver)
{
    int ch = '\0';
    int specified_local_asn = 0;
    while ((ch = getopt(argc, argv, "hf:a:")) != -1)
    {
        switch (ch)
        {
        case 'h':
            help();
            exit(EXIT_SUCCESS);
        case 'f':
            size_t fname_len = strlen(optarg);
            memcpy(fcserver->fname, optarg, fname_len);
            fcserver->fname[fname_len] = '\0';
            break;
        case 'a':
            fcserver->local_asn = (u32) atol(optarg);
            specified_local_asn = 1;
            break;

        default:
            printf("unknow option: %c\n", ch); help();
            break;
        }
    }

    if (!fcserver->fname || strlen(fcserver->fname) == 0)
    {
        // fprintf(stderr, "MUST use -f to specify the asnlist.json\n");
        // exit(-1);
        char *pfname = "assets/asnlist.json";
        memcpy(fcserver->fname, pfname, strlen(pfname));
    }

    if (!specified_local_asn)
    {
        fprintf(stderr, "MUST use -a to specify the local as number.\n");
        exit(-1);
    }

    return 0;
}

int main(int argc, char *argv[])
{
    fcserver_create();
    parse_args(argc, argv, &g_fcserver);


    // 1. 读取SRC-IP和ASN对应关系，必须使用-f指定asnlist.json位置就行
    //     不指定则需要默认bin/server执行，否则会报错
    fcserver_hashtable_create(&g_fcserver.ht);
    read_asn_ips();
    htbl_display(&g_fcserver.ht);
    printf("=====================================================\n");
    print_asn_ips();
    printf("=====================================================\n");

    // 2. 监听等待连接
    broadcast_server_create();
    bgpd_server_create();

    // 销毁fcserver
    fcserver_destroy();

    return 0;
}
