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

/*
    static void
print(const cJSON* root)
{
    char *output = cJSON_Print(root);
    printf("%s\n", output);
    free(output);
}
*/

    static cJSON *
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
read_asn_ips()
{
    cJSON *root = NULL, *asn_list = NULL;
    cJSON *elem = NULL, *asn = NULL,  *acs = NULL;
    cJSON *ipv4 = NULL, *ipv6 = NULL, *ip4s = NULL, *ip6s = NULL;
    cJSON *addr = NULL, *prefix_len = NULL;
    node_as_t meta = {0};
    ht_node_as_t *node = NULL;
    int size = 0, i = 0, j = 0, addr_num = 0, ret = 0;

    root = cjson_root_ptr(g_fcserver.fname);
    assert(root);
    asn_list = cJSON_GetObjectItem(root, "asn_list");
    assert(asn_list);
    size = cJSON_GetArraySize(asn_list);
    g_fcserver.asns_num = size;

    for (i=0; i<size; ++i)
    {
        elem = cJSON_GetArrayItem(asn_list, i);
        // print(elem);
        asn = cJSON_GetObjectItem(elem, "asn");
        acs = cJSON_GetObjectItem(elem, "acs");
        ip4s = cJSON_GetObjectItem(elem, "ip4s");
        ip6s = cJSON_GetObjectItem(elem, "ip6s");
        ipv4 = cJSON_GetObjectItem(acs, "ipv4");
        ipv6 = cJSON_GetObjectItem(acs, "ipv6");

        meta.asn = asn->valueint;
        memcpy(meta.ap.acs.ipv4, ipv4->valuestring,
                strlen(ipv4->valuestring));
        memcpy(meta.ap.acs.ipv6, ipv6->valuestring,
                strlen(ipv6->valuestring));
        addr_num = cJSON_GetArraySize(ip4s);
        for (j=0; j<addr_num; ++j)
        {
            elem = cJSON_GetArrayItem(ip4s, j);
            addr = cJSON_GetObjectItem(elem, "addr");
            prefix_len = cJSON_GetObjectItem(elem, "prefixlen");
            meta.ap.prefix.ip4s[j].prefix_length = prefix_len->valueint;
            inet_pton(AF_INET, addr->valuestring, &meta.ap.prefix.ip4s[j].ip);
        }
        meta.ap.prefix.ip4s_num = addr_num;
        addr_num = cJSON_GetArraySize(ip6s);
        for (j=0; j<addr_num; ++j)
        {
            elem = cJSON_GetArrayItem(ip6s, j);
            addr = cJSON_GetObjectItem(elem, "addr");
            prefix_len = cJSON_GetObjectItem(elem, "prefixlen");
            meta.ap.prefix.ip6s[j].prefix_length = prefix_len->valueint;
            inet_pton(AF_INET6, addr->valuestring, &meta.ap.prefix.ip6s[j].ip);
        }
        meta.ap.prefix.ip6s_num = addr_num;
        g_fcserver.asns[i] = meta.asn;
        node = htbl_meta_insert(&g_fcserver.ht, &meta, &ret);
        if (!node)
        {
            fprintf(stderr, "insert failed\n");
            return -1;
        }
    }

    cJSON_Delete(root);

    return 0;
}

    void
print_asn_ips()
{
    int i=0, j=0;
    node_as_t meta;
    ht_node_as_t *node;
    char ipstr[INET6_ADDRSTRLEN] = {0};
    htbl_ctx_t *ht = &g_fcserver.ht;

    printf("asns_num: %d\n", g_fcserver.asns_num);
    for (i=0; i<g_fcserver.asns_num; ++i)
    {
        meta.asn = g_fcserver.asns[i];
        node = htbl_meta_find(ht, &meta);

        if (node) {
            printf("asn: %d\n", node->asn);
            printf("  acs:\n");
            printf("    ipv4: %s\n", node->ap.acs.ipv4);
            printf("    ipv6: %s\n", node->ap.acs.ipv6);
            printf("  prefix:\n");
            for (j=0; j<node->ap.prefix.ip4s_num; ++j)
            {
                inet_ntop(AF_INET, &node->ap.prefix.ip4s[j].ip,
                        ipstr, (socklen_t)sizeof(ipstr));
                printf("    ipv4: %s/%d\n",
                        ipstr, node->ap.prefix.ip4s[j].prefix_length);
            }
            for (j=0; j<node->ap.prefix.ip6s_num; ++j)
            {
                inet_ntop(AF_INET6, &node->ap.prefix.ip6s[j].ip,
                        ipstr, (socklen_t)sizeof(ipstr));
                printf("    ipv6: %s/%d\n",
                        ipstr, node->ap.prefix.ip6s[j].prefix_length);
            }

            htbl_node_drop(ht, node);
        }

        if (node)
        {
            htbl_node_delete(ht, node);
            node = NULL;
        }
    }
}
