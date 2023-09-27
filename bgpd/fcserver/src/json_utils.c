/********************************************************************************
 * File Name:    json_utils.c
 * Author:       basilguo@163.com
 * Created Time: 2023-09-27 09:06:08
 * Description:
 ********************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "cJSON.h"
#include "common.h"
#include "utils.h"
#include "mln_hash.h"

    static char *
read_file(const char *fname)
{
    FILE *fp = NULL;
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

    static void
print(const cJSON* root)
{
    char *output = cJSON_Print(root);
    printf("%s\n", output);
    free(output);
}

    cJSON *
cjson_root_ptr(const char *fname)
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

int
read_asn_ips(const char *fname, fcserver_t *fcserver,
        mln_hash_t *h, int *asns, int *asns_size)
{
    cJSON *root = NULL, *asn_list = NULL;
    cJSON *elem = NULL, *asn = NULL,  *acs = NULL;
    cJSON *ipv4 = NULL, *ipv6 = NULL, *ip4s = NULL, *ip6s = NULL;
    cJSON *addr = NULL, *prefix_len = NULL;
    node_as_t *node = NULL;// *ret = NULL;
    int size = 0, i = 0, j = 0, addr_num = 0;;

    root = cjson_root_ptr(fname);
    assert(root);
    asn_list = cJSON_GetObjectItem(root, "asn_list");
    assert(asn_list);
    size = cJSON_GetArraySize(asn_list);
    *asns_size = size;

    for (i=0; i<size; ++i)
    {
        elem = cJSON_GetArrayItem(asn_list, i);
        print(elem);
        asn = cJSON_GetObjectItem(elem, "asn");
        acs = cJSON_GetObjectItem(elem, "acs");
        ip4s = cJSON_GetObjectItem(elem, "ip4s");
        ip6s = cJSON_GetObjectItem(elem, "ip6s");
        ipv4 = cJSON_GetObjectItem(acs, "ipv4");
        ipv6 = cJSON_GetObjectItem(acs, "ipv6");

        if ((node = (node_as_t*)malloc(sizeof(node_as_t))) == NULL)
        {
            fprintf(stderr, "malloc failed\n");
            return -1;
        }
        memset(node, 0, sizeof(node_as_t));
        node->asn = asn->valueint;
        memcpy(node->ap.acs.ipv4, ipv4->valuestring,
                strlen(ipv4->valuestring));
        memcpy(node->ap.acs.ipv6, ipv6->valuestring,
                strlen(ipv6->valuestring));
        addr_num = cJSON_GetArraySize(ip4s);
        for (j=0; j<addr_num; ++j)
        {
            elem = cJSON_GetArrayItem(ip4s, j);
            addr = cJSON_GetObjectItem(elem, "addr");
            prefix_len = cJSON_GetObjectItem(elem, "prefixlen");
            node->ap.prefix.ipv4[j].prefix_length = prefix_len->valueint;
            inet_pton(AF_INET, addr->valuestring, &node->ap.prefix.ipv4[j].ip);
        }
        addr_num = cJSON_GetArraySize(ip6s);
        for (j=0; j<addr_num; ++j)
        {
            elem = cJSON_GetArrayItem(ip6s, j);
            addr = cJSON_GetObjectItem(elem, "addr");
            prefix_len = cJSON_GetObjectItem(elem, "prefixlen");
            node->ap.prefix.ipv6[j].prefix_length = prefix_len->valueint;
            inet_pton(AF_INET, addr->valuestring, &node->ap.prefix.ipv6[j].ip);
        }
        asns[i] = node->asn;
        if (mln_hash_insert(h, &(node->asn), node) < 0)
        {
            fprintf(stderr, "insert failed\n");
            return -1;
        }
    }

    return 0;
}

