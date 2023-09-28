/********************************************************************************
* File Name:    server.c
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
#include "mln_hash.h"

static void help()
{
    printf("\t-h                              print this message.\n");
    printf("\t-f <asnlist.json location>     specify the location of asnlist.json\n");
}

static int parse_args(int argc, char *argv[], char *fname)
{
    int ch = '\0';
    while ((ch = getopt(argc, argv, "hf:")) != -1)
    {
        switch (ch)
        {
        case 'h':
            help();
            exit(EXIT_SUCCESS);
        case 'f':
            size_t fname_len = strlen(optarg);
            memcpy(fname, optarg, fname_len);
            fname[fname_len] = '\0';
            break;
        default:
            printf("unknow option: %c\n", ch); help();
            break;
        }
    }

    if (!fname || strlen(fname) == 0)
    {
        // fprintf(stderr, "MUST use -f to specify the asnlist.json\n");
        // exit(-1);
        char *pfname = "assets/asnlist.json";
        memcpy(fname, pfname, strlen(pfname));
    }

    return 0;
}

int main(int argc, char *argv[])
{
    char fname[BUFSIZ] = {0};
    int asns[FCSRV_MAX_LINK_AS] = {0};
    int asns_size = 0;
    fcserver_t fcserver = {0};
    htbl_ctx_t ht;

    // 1. 读取SRC-IP和ASN对应关系，必须使用-f指定asnlist.json位置就行
    //     不指定则需要默认bin/server执行，否则会报错
    parse_args(argc, argv, fname);
    create_fcserver_hashtable(&ht);
    read_asn_ips(fname, &fcserver, &ht, asns, &asns_size);
    print_asn_ips(&ht, asns, asns_size);

    // 2.

    // mln_hash_free(ht, M_HASH_F_VAL);

    return 0;
}
