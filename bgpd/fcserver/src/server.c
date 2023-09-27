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
#include "json_utils.h"
#include "mln_hash.h"

    static void
help()
{
    printf("\t-h                              print this message.\n");
    printf("\t-f <asnlist.json location>     specify the location of asnlist.json\n");
}

    static int
parse_args(int argc, char *argv[], char *fname)
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

    if (!fname)
    {
        fprintf(stderr, "MUST use -f to specify the asnlist.json\n");
        exit(-1);
    }

    return 0;
}

    static mln_u64_t
calc_handler(mln_hash_t *ht, void *key)
{
    return *((int *)key) % ht->len;
}

    static int
cmp_handler(mln_hash_t *ht, void *key1, void *key2)
{
    return !(*((int *)key1) - *((int *)key2));
}

static int
create_fcserver_hashtable(mln_hash_t **ht)
{
    struct mln_hash_attr htattr;

    htattr.pool = NULL;
    htattr.pool_alloc = NULL;
    htattr.pool_free = NULL;
    htattr.hash = calc_handler;
    htattr.cmp = cmp_handler;
    htattr.free_key = NULL;
    htattr.free_val = NULL;
    htattr.len_base = FCSRV_MAX_LINK_AS;
    htattr.expandable = 0;
    htattr.calc_prime = 0;

    if ((*ht = mln_hash_new(&htattr)) == NULL)
    {
        fprintf(stderr, "Hash init failed\n");
        return -1;
    }

    return 0;
}

    int
main(int argc, char *argv[])
{
    char fname[BUFSIZ] = {0};
    int i = 0;
    int asns[FCSRV_MAX_LINK_AS] = {0};
    int asns_size = 0;
    mln_hash_t *ht = NULL;
    fcserver_t fcserver = {0};
    node_as_t *node;

    // 1. 读取SRC-IP和ASN对应关系，必须使用-f指定asnlist.json位置就行
    parse_args(argc, argv, fname);
    create_fcserver_hashtable(&ht);
    assert(ht);
    read_asn_ips(fname, &fcserver, ht, asns, &asns_size);

    for (i=0; i<asns_size; ++i)
    {
        node = mln_hash_search(ht, &asns[i]);
        printf("asn = %d, ipv4 = %s, ipv6 = %s\n",
                node->asn, node->ap.acs.ipv4, node->ap.acs.ipv6);
    }

    // 2.

    mln_hash_free(ht, M_HASH_F_VAL);

    return 0;
}
