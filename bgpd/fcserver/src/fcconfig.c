/********************************************************************************
 * File Name:    fcconfig.c
 * Author:       basilguo@163.com
 * Created Time: 2023-12-19 08:57:06
 * Description:  JSON UTILS
 ********************************************************************************/

#include "fcconfig.h"
#include "cJSON.h"

/**
 * If the user forgets to remove the tail '/', we need to properly accept that.
 * @param path      path
 * @param filename  filename
 * @return          Return the combined fullpath
 * */
static inline char *
fc_combine_path(const char *path, const char *filename)
{
    size_t path_len = strlen(path);
    size_t filename_len = strlen(filename);
    size_t combined_len = path_len + filename_len + 2; // 2 for '/' and '\0'

    char *combined_path = (char *)malloc(combined_len);
    if (combined_path == NULL)
    {
        fprintf(stderr, "malloc for combined_path failed\n");
        return NULL;
    }
    memset(combined_path, 0, combined_len);

    memcpy(combined_path, path, strlen(path));
    if (path_len > 0 && path[path_len - 1] != '/')
    {
        strcat(combined_path, "/");
    }

    strcat(combined_path, filename);

    return combined_path;
}

/**
 * Generated the uppercase of string.
 * @param str   input string
 * @param size  input string size
 * @return      output the uppercase of input string.
 *              you're expected to free it to recycle the memory.
 * */
static inline char *
fc_utils_str_toupper(const char *str, int size)
{
    int i = 0;
    char *outputstr = NULL;

    outputstr = (char *)calloc(size + 1, sizeof(char));
    if (outputstr)
    {

        for (i = 0; i < size; ++i)
        {
            outputstr[i] = toupper(str[i]);
        }

        outputstr[size] = '\0';
    }

    return outputstr;
}

int fc_cfg_set_dp_mode(const char *mode_string)
{
    int size = 0;
    char *modestr = NULL;

    size = strlen(mode_string);
    modestr = fc_utils_str_toupper(mode_string, size);
    FC_ASSERT_RETP(modestr);

    g_fc_server.use_data_plane = FC_DP_MODE_NONE;
    if (strcmp(modestr, "LINUX") == 0)
    {
        g_fc_server.use_data_plane = FC_DP_MODE_LINUX;
    }
    else if (strcmp(modestr, "VPP") == 0)
    {
        g_fc_server.use_data_plane = FC_DP_MODE_VPP;
    }
    else if (strcmp(modestr, "H3C") == 0)
    {
        g_fc_server.use_data_plane = FC_DP_MODE_H3C;
    }
    free(modestr);

    return 0;
}

int fc_set_log_mode(const char *mode_string)
{
    int size = 0;
    char *modestr = NULL;

    size = strlen(mode_string);
    modestr = fc_utils_str_toupper(mode_string, size);
    FC_ASSERT_RETP(modestr);

    g_fc_server.log_mode = FC_LOG_LEVEL_INFO;
    if (strcmp(modestr, "EMERGE") == 0)
    {
        g_fc_server.log_mode = FC_LOG_LEVEL_EMERG;
    }
    else if (strcmp(modestr, "ERROR") == 0)
    {
        g_fc_server.log_mode = FC_LOG_LEVEL_ERROR;
    }
    else if (strcmp(modestr, "WARNING") == 0)
    {
        g_fc_server.log_mode = FC_LOG_LEVEL_WARNING;
    }
    else if (strcmp(modestr, "INFO") == 0)
    {
        g_fc_server.log_mode = FC_LOG_LEVEL_INFO;
    }
    else if (strcmp(modestr, "DEBUG"))
    {
        g_fc_server.log_mode = FC_LOG_LEVEL_DEBUG;
    }
    else if (strcmp(modestr, "VERBOSE"))
    {
        g_fc_server.log_mode = FC_LOG_LEVEL_VERBOSE;
    }

    free(modestr);

    return 0;
}

static char *
fc_read_file(const char *fname)
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

static inline void
fc_cjson_print(const cJSON *root)
{
    char *output = cJSON_Print(root);
    printf("%s\n", output);
    free(output);
}

static inline cJSON *
fc_cjson_root_ptr(const char *fname)
{
    cJSON *root = NULL;
    char *content = fc_read_file(fname);

    root = cJSON_Parse(content);

    if (content != NULL)
    {
        free(content);
    }

    return root;
}

static int fc_fill_config_hash_algo_id()
{
    if (!strcmp(g_fc_server.hash_algorithm, "sha256") ||
        !strcmp(g_fc_server.hash_algorithm, "SHA256"))
    {
        g_fc_server.hash_algorithm_id = FC_HASH_ALGO_SHA256;
    }
    else if (!strcmp(g_fc_server.hash_algorithm, "sha1") ||
             !strcmp(g_fc_server.hash_algorithm, "SHA1"))
    {
        g_fc_server.hash_algorithm_id = FC_HASH_ALGO_SHA1;
    }
    else if (!strcmp(g_fc_server.hash_algorithm, "crc32") ||
             !strcmp(g_fc_server.hash_algorithm, "CRC32"))
    {
        g_fc_server.hash_algorithm_id = FC_HASH_ALGO_CRC32;
    }
    else if (!strcmp(g_fc_server.hash_algorithm, "md5") ||
             !strcmp(g_fc_server.hash_algorithm, "MD5"))
    {
        g_fc_server.hash_algorithm_id = FC_HASH_ALGO_MD5;
    }
    else
    {
        g_fc_server.hash_algorithm_id = FC_HASH_ALGO_UNKNOWN;
    }

    return 0;
}

int fc_read_config(void)
{
    int i = 0, j = 0, ret = 0;
    char *fpath = NULL;
    cJSON *root = NULL, *asn_list = NULL, *cert = NULL;
    cJSON *elem = NULL, *asn = NULL, *acs = NULL, *nics = NULL;
    cJSON *ipv4 = NULL, *ipv6 = NULL, *ifaddr = NULL, *ifname = NULL;
    FC_node_as_t meta = {0};
    FC_ht_node_as_t *node = NULL;

    root = fc_cjson_root_ptr(g_fc_server.config_fname);
    FC_ASSERT_RETP(root);

    // local_asn
    elem = cJSON_GetObjectItem(root, "local_asn");
    g_fc_server.local_asn = elem->valueint;
    // hash_alogrithm
    elem = cJSON_GetObjectItem(root, "hash_algorithm");
    g_fc_server.hash_algorithm = elem->valuestring;
    fc_fill_config_hash_algo_id();

    // log_mode
    elem = cJSON_GetObjectItem(root, "log_mode");
    fc_set_log_mode(elem->valuestring);
    // clear fc db
    elem = cJSON_GetObjectItem(root, "clear_fc_db");
    g_fc_server.clear_fc_db = elem->type == cJSON_True ? true : false;
    // use data plane - nftables
    elem = cJSON_GetObjectItem(root, "use_data_plane");
    fc_cfg_set_dp_mode(elem->valuestring);
    // certs location
    elem = cJSON_GetObjectItem(root, "certs_location");
    g_fc_server.certs_location = strdup(elem->valuestring);
    // private key
    elem = cJSON_GetObjectItem(root, "private_key_fname");
    g_fc_server.prikey_fname = strdup(elem->valuestring);
    fpath = fc_combine_path(g_fc_server.certs_location,
                            g_fc_server.prikey_fname);
    fc_read_eckey_from_file(fpath, 0, &g_fc_server.prikey);
    free(fpath);
    fpath = NULL;
    // router info list
    if (g_fc_server.use_data_plane == FC_DP_MODE_H3C)
    {
        cJSON *router_list = NULL, *router_info = NULL;
        FC_router_info_t *curr_router = NULL, *next_router = NULL;
        router_list = cJSON_GetObjectItem(root, "router_info_list");
        FC_ASSERT_RETP(router_list);
        g_fc_server.routers_num = cJSON_GetArraySize(router_list);
        for (i = 0; i < g_fc_server.routers_num; ++i)
        {
            curr_router = calloc(1, sizeof(FC_router_info_t));
            next_router = g_fc_server.routers;
            curr_router->next = next_router;
            g_fc_server.routers = curr_router;
            router_info = cJSON_GetArrayItem(router_list, i);
            if (g_fc_server.log_mode >= FC_LOG_LEVEL_DEBUG)
            {
                fc_cjson_print(router_info);
            }

            elem = cJSON_GetObjectItem(router_info, "bgpid");
            FC_ASSERT_RETP(elem);
            inet_pton(AF_INET, elem->valuestring, &curr_router->bgpid);
            curr_router->bgpid = ntohl(curr_router->bgpid);
            elem = cJSON_GetObjectItem(router_info, "host");
            FC_ASSERT_RETP(elem);
            memcpy(curr_router->host, elem->valuestring,
                   strlen(elem->valuestring));
            elem = cJSON_GetObjectItem(router_info, "port");
            FC_ASSERT_RETP(elem);
            curr_router->port = elem->valueint;
            elem = cJSON_GetObjectItem(router_info, "username");
            FC_ASSERT_RETP(elem);
            memcpy(curr_router->username, elem->valuestring,
                   strlen(elem->valuestring));
            elem = cJSON_GetObjectItem(router_info, "password");
            FC_ASSERT_RETP(elem);
            memcpy(curr_router->password, elem->valuestring,
                   strlen(elem->valuestring));
        }
    }

    // as info list
    asn_list = cJSON_GetObjectItem(root, "as_info_list");
    g_fc_server.asns_num = cJSON_GetArraySize(asn_list);

    for (i = 0; i < g_fc_server.asns_num; ++i)
    {
        memset(&meta, 0, sizeof(meta));
        elem = cJSON_GetArrayItem(asn_list, i);
        if (g_fc_server.log_mode >= FC_LOG_LEVEL_DEBUG)
        {
            fc_cjson_print(elem);
        }

        asn = cJSON_GetObjectItem(elem, "asn");
        cert = cJSON_GetObjectItem(elem, "cert");
        nics = cJSON_GetObjectItem(elem, "nics");
        acs = cJSON_GetObjectItem(elem, "acs");

        meta.asn = asn->valueint;
        memcpy(meta.cert, cert->valuestring, strlen(cert->valuestring));
        fpath = fc_combine_path(g_fc_server.certs_location, meta.cert);
        fc_get_ecpubkey_and_ski(meta.asn, fpath, &meta.pubkey, meta.ski);
        printf("meta.ski: ");
        for (j = 0; j < FC_SKI_LENGTH; j++)
        {
            printf("%02X", meta.ski[j]);
        }
        printf("\n");

        if (meta.asn == g_fc_server.local_asn)
        {
            g_fc_server.pubkey = meta.pubkey;
            memcpy(g_fc_server.ski, meta.ski, FC_SKI_LENGTH);
        }
        free(fpath);
        fpath = NULL;

        g_fc_server.nics_num = cJSON_GetArraySize(nics);
        for (j = 0; j < g_fc_server.nics_num; ++j)
        {
            elem = cJSON_GetArrayItem(nics, j);
            memcpy(g_fc_server.nics[j], elem->valuestring,
                   strlen(elem->valuestring));
        }

        ipv4 = cJSON_GetObjectItem(acs, "ipv4");
        meta.acs.ipv4_num = cJSON_GetArraySize(ipv4);
        for (j = 0; j < meta.acs.ipv4_num; ++j)
        {
            elem = cJSON_GetArrayItem(ipv4, j);
            ifaddr = cJSON_GetObjectItem(elem, "ifaddr");
            ifname = cJSON_GetObjectItem(elem, "ifname");
            memcpy(meta.acs.ipv4[j].ifaddr, ifaddr->valuestring,
                   strlen(ifaddr->valuestring));
            memcpy(meta.acs.ipv4[j].ifname, ifname->valuestring,
                   strlen(ifname->valuestring));
        }

        ipv6 = cJSON_GetObjectItem(acs, "ipv6");
        meta.acs.ipv6_num = cJSON_GetArraySize(ipv6);
        for (j = 0; j < meta.acs.ipv6_num; ++j)
        {
            elem = cJSON_GetArrayItem(ipv6, j);
            ifaddr = cJSON_GetObjectItem(elem, "ifaddr");
            ifname = cJSON_GetObjectItem(elem, "ifname");
            memcpy(meta.acs.ipv6[j].ifaddr, ifaddr->valuestring,
                   strlen(ifaddr->valuestring));
            memcpy(meta.acs.ipv6[j].ifname, ifname->valuestring,
                   strlen(ifname->valuestring));
        }

        g_fc_server.asns[i] = meta.asn;
        node = htbl_meta_insert(&g_fc_server.ht_as, &meta, &ret);
        if (!node)
        {
            printf("insert failed\n");
            return -1;
        }
        printf("====================================================\n");
    }

    cJSON_Delete(root);
    free(g_fc_server.config_fname);
    g_fc_server.config_fname = NULL;

    return 0;
}
