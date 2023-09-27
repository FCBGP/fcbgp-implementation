/********************************************************************************
* File Name:    test_libhtable.c
* Author:       basilguo@163.com
* Created Time: 2023-09-26 05:58:59
* Description:
********************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "libhtable.h"

typedef struct acs_st
{
    char ipv4[16];
    char ipv6[40];
} acs_t;

typedef struct as_info_s
{
    unsigned int asn;
    acs_t acs;
} as_info_t;

void *node_create_func(void)
{
    return malloc(sizeof(as_info_t));
}

int node_destroy_func(void *node)
{
    free(node);
    node = NULL;
    return 0;
}

int node_display_func(void *node)
{
    as_info_t *as = node;
    printf("%d, %s, %s\n", as->asn, as->acs.ipv4, as->acs.ipv6);
    return 0;
}

int node_hash_func(void *node)
{
    as_info_t *as = node;
    int hash = 0;
    hash = as->asn;
    return hash;
}

int meta_hash_func(void *meta)
{
    as_info_t *as = meta;
    return as->asn;
}

int meta_cmp_func(void *base, void *meta)
{
    return ((as_info_t*)base)->asn - ((as_info_t*)meta)->asn;
}

int meta_save_func(void *base, void *meta)
{
    return 0;
}

int main(int argc, char *argv[])
{
    htbl_ops_t ops = {
        .node_create_func = node_create_func,
        .node_destroy_func = node_destroy_func,
        .node_display_func = node_display_func,
        .node_hash_func = node_hash_func,
        .meta_hash_func = meta_hash_func,
        .meta_cmp_func = meta_cmp_func,
        .meta_save_func = NULL
    };

    htbl_ctx_t *ctx = htbl_create(100, &ops);
    htbl_init(ctx);

    char *ipv4 = "192.168.1.1";
    as_info_t as = {0};

    as.asn = 10;
    memcpy(as.acs.ipv4, ipv4, strlen(ipv4));

    htbl_meta_insert(ctx, &as);

    htbl_fini(ctx);
    htbl_destrop(ctx);



    return 0;
}
