/********************************************************************************
 * File Name:    read_asn.c
 * Author:       basilguo@163.com
 * Created Time: 2023-09-25 11:20:34
 * Description:
 ********************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cJSON.h"
#include "mln_hash.h"

#define MAX_AS 256

char *read_file(const char *fname)
{
    FILE* fp = NULL;
    long length = 0;
    char *content = NULL;
    size_t read_chars = 0;

    fp = fopen(fname, "rb");
    if (fp == NULL)
    {
        goto cleanup;
    }

    // get the length
    if (fseek(fp, 0, SEEK_END) != 0)
    {
        goto cleanup;
    }

    length = ftell(fp);
    if (length < 0)
    {
        goto cleanup;
    }

    if (fseek(fp, 0, SEEK_SET) != 0)
    {
        goto cleanup;
    }

    // alloc the mem
    content = (char *)malloc((size_t)length + sizeof(""));
    if (content == NULL)
    {
        goto cleanup;
    }

    // read the file into mem
    read_chars = fread(content, sizeof(char), (size_t)length, fp);
    if ((long)read_chars != length)
    {
        free(content);
        content = NULL;
        goto cleanup;
    }

    content[read_chars] = '\0';

cleanup:
    if (fp != NULL)
    {
        fclose(fp);
    }

    return content;
}

void print(const cJSON* root)
{
    char *output = cJSON_Print(root);
    printf("%s\n", output);
    free(output);
}

cJSON *parse_file(const char *fname)
{
    cJSON *root = NULL;
    char *content = read_file(fname);

    root = cJSON_Parse(content);

    if (content != NULL)
    {
        free(content);
    }

    return root;
}

typedef struct acs_info_s
{
    char ipv4[16];
    char ipv6[40];
} acs_info_t;

typedef struct as_info_s
{
    int asn;
    acs_info_t acs;
} as_info_t;

int parse_json(as_info_t *as_info, int *as_info_size)
{

    cJSON *root = NULL, *asn_list = NULL;
    cJSON *elem = NULL, *asn = NULL, *acs = NULL;
    cJSON *ipv4 = NULL, *ipv6 = NULL;
    int size = 0, i = 0;

    root = parse_file("asnlist.json");
    asn_list = cJSON_GetObjectItem(root, "asn_list");
    size = cJSON_GetArraySize(asn_list);

    for (i=0; i<size; ++i)
    {
        elem = cJSON_GetArrayItem(asn_list, i);
        print(elem);
        asn = cJSON_GetObjectItem(elem, "asn");
        acs = cJSON_GetObjectItem(elem, "acs");
        ipv4 = cJSON_GetObjectItem(acs, "ipv4");
        ipv6 = cJSON_GetObjectItem(acs, "ipv6");

        as_info[i].asn = (asn->valueint);
        memcpy(as_info[i].acs.ipv4, ipv4->valuestring,
                strlen(ipv4->valuestring));
        memcpy(as_info[i].acs.ipv6, ipv6->valuestring,
                strlen(ipv6->valuestring));
    }

    *as_info_size = size;

    cJSON_Delete(root);

    return 0;
}

static mln_u64_t calc_handler(mln_hash_t *h, void *key)
{
    return *((int *)key) % h->len;
}

static int cmp_handler(mln_hash_t *h, void *key1, void *key2)
{
    return !(*((int *)key1) - *((int *)key2));
}

int test1()
{
    as_info_t as_info[MAX_AS] = {0};
    int as_info_size = 0;
    int i = 0;

    parse_json(as_info, &as_info_size);

    for (i=0; i<as_info_size; ++i)
    {
        printf("asn = %d, ipv4 = %s, ipv6 = %s.\n",
                as_info[i].asn, as_info[i].acs.ipv4, as_info[i].acs.ipv6);
    }


    return 0;
}

int parse_json2(mln_hash_t *h, int *asns, int *asns_size)
{
    as_info_t *as_info, *ret;
    cJSON *root = NULL, *asn_list = NULL;
    cJSON *elem = NULL, *asn = NULL, *acs = NULL;
    cJSON *ipv4 = NULL, *ipv6 = NULL;
    int size = 0, i = 0;

    root = parse_file("asnlist.json");
    asn_list = cJSON_GetObjectItem(root, "asn_list");
    size = cJSON_GetArraySize(asn_list);

    for (i=0; i<size; ++i)
    {
        elem = cJSON_GetArrayItem(asn_list, i);
        print(elem);
        asn = cJSON_GetObjectItem(elem, "asn");
        acs = cJSON_GetObjectItem(elem, "acs");
        ipv4 = cJSON_GetObjectItem(acs, "ipv4");
        ipv6 = cJSON_GetObjectItem(acs, "ipv6");

        as_info = (as_info_t*)malloc(sizeof(as_info_t));
        if (as_info == NULL)
        {
            fprintf(stderr, "malloc failed\n");
            return -1;
        }
        memset(as_info, 0, sizeof(as_info_t));

        as_info->asn = asn->valueint;
        memcpy(as_info->acs.ipv4, ipv4->valuestring,
                strlen(ipv4->valuestring));
        memcpy(as_info->acs.ipv6, ipv6->valuestring,
                strlen(ipv6->valuestring));

        if (mln_hash_insert(h, &(as_info->asn), as_info) < 0)
        {
            fprintf(stderr, "insert failed\n");
            return -1;
        }

        asns[i] = asn->valueint;
    }

    *asns_size = size;

    cJSON_Delete(root);

    return 0;
}

int test2()
{

    mln_hash_t *h;
    int i = 0;
    struct mln_hash_attr hattr;
    int asns[MAX_AS] = {0};
    int asns_size = 0;
    as_info_t *ret;

    hattr.pool = NULL;
    hattr.pool_alloc = NULL;
    hattr.pool_free = NULL;
    hattr.hash = calc_handler;
    hattr.cmp = cmp_handler;
    hattr.free_key = NULL;
    hattr.free_val = NULL;
    hattr.len_base = MAX_AS;
    hattr.expandable = 0;
    hattr.calc_prime = 0;

    if (( h = mln_hash_new(&hattr)) == NULL)
    {
        fprintf(stderr, "Hash init failed\n");
        return -1;
    }

    parse_json2(h, asns, &asns_size);

    for (i=0; i<asns_size; ++i)
    {
        ret = mln_hash_search(h, &asns[i]);
        printf("asn = %d, ipv4 = %s, ipv6 = %s.\n",
                ret->asn, ret->acs.ipv4, ret->acs.ipv6);
    }

    mln_hash_free(h, M_HASH_F_VAL);

    return 0;
}

int main(void)
{
    test1();
    printf("=================================================\n");
    test2();

    return 0;
}
