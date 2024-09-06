/********************************************************************************
 * File Name:    fcconfig.c
 * Author:       basilguo@163.com
 * Created Time: 2023-12-19 08:57:06
 * Description:  JSON UTILS
 ********************************************************************************/

#include "cJSON.h"

#include "defines.h"
#include "fcconfig.h"
#include "sigutils.h"
#include "strutils.h"

static char *
fc_read_file(const char *const fname)
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
fc_cjson_print(const cJSON *const root)
{
    char *output = cJSON_Print(root);
    printf("%s\n", output);
    FC_MEM_FREE(output);
}

static inline cJSON *
fc_cjson_root_ptr(const char *const fname)
{
    cJSON *root = NULL;
    char *content = fc_read_file(fname);

    root = cJSON_Parse(content);

    if (content != NULL)
    {
        FC_MEM_FREE(content);
    }

    return root;
}

int fc_cfg_set_local_asn(uint32_t local_asn)
{
    g_fc_server.local_asn = local_asn;
    return 0;
}

int fc_set_listen_port(int listen_port)
{
    if (listen_port <= 0 || listen_port > 65535)
    {
        g_fc_server.listen_port = FC_CFG_DEFAULT_LISTEN_PORT;
    }
    else
    {
        g_fc_server.listen_port = listen_port;
    }
    return 0;
}

int fc_cfg_set_hash_algo_id(const char *const hash_algo_str)
{
    int size = 0;

    memcpy(g_fc_server.hash_algorithm, hash_algo_str,
           strlen(hash_algo_str));
    size = strlen(g_fc_server.hash_algorithm);
    fc_utils_str_toupper(g_fc_server.hash_algorithm, size);

    if (strcmp(g_fc_server.hash_algorithm, "SHA256") == 0)
    {
        g_fc_server.hash_algorithm_id = FC_HASH_ALGO_SHA256;
    }
    else if (strcmp(g_fc_server.hash_algorithm, "SHA1") == 0)
    {
        g_fc_server.hash_algorithm_id = FC_HASH_ALGO_SHA1;
    }
    else if (strcmp(g_fc_server.hash_algorithm, "CRC32") == 0)
    {
        g_fc_server.hash_algorithm_id = FC_HASH_ALGO_CRC32;
    }
    else if (strcmp(g_fc_server.hash_algorithm, "MD5") == 0)
    {
        g_fc_server.hash_algorithm_id = FC_HASH_ALGO_MD5;
    }
    else
    {
        memcpy(g_fc_server.hash_algorithm, FC_CFG_DEFAULT_HASH_ALGO,
               strlen(FC_CFG_DEFAULT_HASH_ALGO));
        g_fc_server.hash_algorithm_id = FC_CFG_DEFAULT_HASH_ALGO_ID;
    }
    return 0;
}

int fc_cfg_set_log_mode(const char *const log_mode_str)
{
    int size = 0;
    char *modestr = NULL;

    size = strlen(log_mode_str);
    modestr = malloc(size);
    memcpy(modestr, log_mode_str, size);
    FC_ASSERT_RETP(modestr);
    fc_utils_str_toupper(modestr, size);

    if (strcmp(modestr, "EMERGE") == 0)
    {
        g_fc_server.log_level = FC_LOG_LEVEL_EMERG;
    }
    else if (strcmp(modestr, "ERROR") == 0)
    {
        g_fc_server.log_level = FC_LOG_LEVEL_ERROR;
    }
    else if (strcmp(modestr, "WARNING") == 0)
    {
        g_fc_server.log_level = FC_LOG_LEVEL_WARNING;
    }
    else if (strcmp(modestr, "INFO") == 0)
    {
        g_fc_server.log_level = FC_LOG_LEVEL_INFO;
    }
    else if (strcmp(modestr, "DEBUG"))
    {
        g_fc_server.log_level = FC_LOG_LEVEL_DEBUG;
    }
    else if (strcmp(modestr, "VERBOSE"))
    {
        g_fc_server.log_level = FC_LOG_LEVEL_VERBOSE;
    }
    else
    {
        g_fc_server.log_level = FC_CFG_DEFAULT_LOG_LEVEL;
    }

    free(modestr);
    return 0;
}

int fc_cfg_set_dp_mode(const char *const dp_mode_str)
{
    int size = 0;
    char *modestr = NULL;

    size = strlen(dp_mode_str);
    modestr = calloc(size + 1, sizeof(char));
    FC_ASSERT_RETP(modestr);
    memcpy(modestr, dp_mode_str, size);
    fc_utils_str_toupper(modestr, size);

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
    else
    {
        g_fc_server.use_data_plane = FC_DP_MODE_NONE;
    }

    free(modestr);

    return 0;
}

int fc_cfg_set_certs_location(const char *const certs_location)
{
    if (g_fc_server.certs_location)
    {
        FC_MEM_FREE(g_fc_server.certs_location);
    }

    g_fc_server.certs_location = strdup(certs_location);

    return 0;
}

static void
fc_json_read_local_asn(const cJSON *const root)
{
    cJSON *elem = NULL;
    elem = cJSON_GetObjectItem(root, "local_asn");
    FC_ASSERT_RETP(elem);
    fc_cfg_set_local_asn(elem->valueint);
}

static void
fc_json_read_fc_db_fname(const cJSON *const root)
{
    cJSON *elem = NULL;
    elem = cJSON_GetObjectItem(root, "fc_db_fname");
    if (elem)
    {
        g_fc_server.fc_db_fname = strdup(elem->valuestring);
    }
    else
    {
        g_fc_server.fc_db_fname = strdup(FC_CFG_DEFAULT_DB_NAME);
    }
}

static void
fc_json_read_listen_port(const cJSON *const root)
{
    cJSON *elem = NULL;
    elem = cJSON_GetObjectItem(root, "listen_port");
    if (elem)
    {
        fc_set_listen_port(elem->valueint);
    }
    else
    {
        fc_set_listen_port(FC_CFG_DEFAULT_LISTEN_PORT);
    }
}

static void
fc_json_read_hash_algo_id(const cJSON *const root)
{
    cJSON *elem = NULL;

    elem = cJSON_GetObjectItem(root, "hash_algorithm");
    if (elem == NULL)
    {
        memcpy(g_fc_server.hash_algorithm, FC_CFG_DEFAULT_HASH_ALGO,
               strlen(FC_CFG_DEFAULT_HASH_ALGO));
        g_fc_server.hash_algorithm_id = FC_CFG_DEFAULT_HASH_ALGO_ID;
        return;
    }

    fc_cfg_set_hash_algo_id(elem->valuestring);
}

static void
fc_json_read_log_mode(const cJSON *const root)
{
    cJSON *elem = NULL;

    elem = cJSON_GetObjectItem(root, "log_mode");
    if (elem == NULL)
    {
        g_fc_server.log_level = FC_CFG_DEFAULT_LOG_LEVEL;
    }
    else
    {
        fc_cfg_set_log_mode(elem->valuestring);
    }
}

static void
fc_json_read_clear_fc_db(const cJSON *const root)
{
    cJSON *elem = NULL;

    elem = cJSON_GetObjectItem(root, "clear_fc_db");
    if (elem)
    {
        g_fc_server.clear_fc_db =
            elem->type == cJSON_True ? true : false;
    }
    else
    {
        g_fc_server.clear_fc_db = true;
    }
}

static void
fc_json_read_dp_mode(const cJSON *const root)
{
    cJSON *elem = NULL;

    elem = cJSON_GetObjectItem(root, "use_data_plane");
    if (elem == NULL)
    {
        fc_cfg_set_dp_mode(FC_CFG_DEFAULT_DP_MODE);
        return;
    }

    fc_cfg_set_dp_mode(elem->valuestring);
}

static void
fc_json_read_certs_location(const cJSON *const root)
{
    cJSON *elem = NULL;
    elem = cJSON_GetObjectItem(root, "certs_location");
    FC_ASSERT_RETP(elem);
    fc_cfg_set_certs_location(elem->valuestring);
}

static void
fc_json_read_private_key(const cJSON *const root)
{
    cJSON *elem = NULL;
    char *fpath = NULL;
    elem = cJSON_GetObjectItem(root, "private_key_fname");
    FC_ASSERT_RETP(elem);
    g_fc_server.prikey_fname = strdup(elem->valuestring);
    fpath = fc_combine_path(g_fc_server.certs_location,
                            g_fc_server.prikey_fname);
    fc_read_eckey_from_file(fpath, FC_KEY_TYPE_PRIVATE, &g_fc_server.prikey);
    FC_MEM_FREE(fpath);
}

static void
fc_json_read_router_info_list(const cJSON *const root)
{
    int i = 0;
    cJSON *elem = NULL;
    cJSON *router_list = NULL, *router_info = NULL;
    FC_router_info_t *curr_router = NULL, *next_router = NULL;

    if (g_fc_server.use_data_plane == FC_DP_MODE_H3C)
    {
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
            if (g_fc_server.log_level >= FC_LOG_LEVEL_DEBUG)
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

            elem = cJSON_GetObjectItem(router_info, "acl_group_start_index");
            if (elem == NULL)
            {
                curr_router->acl_group_index =
                    FC_CFG_DEFAULT_H3C_ACL_GROUP_START_INDEX;
            }
            else
            {
                curr_router->acl_group_index = elem->valueint;
            }
        }
    }
    else
    {
        TXTYLW("Useless router_info_list configuration "
               "as the data plane is not real router machine.\n");
    }
}

static int fc_json_read_as_info_list(const cJSON *const root)
{
    int i = 0, j = 0, ret = 0;
    char *fpath = NULL;
    cJSON *asn_list = NULL, *elem = NULL;
    cJSON *ipv4 = NULL, *ipv6 = NULL, *ifaddr = NULL, *ifname = NULL;
    cJSON *asn = NULL, *cert = NULL, *nics = NULL, *acs = NULL;
    FC_node_as_t meta = {0};
    FC_ht_node_as_t *node = NULL;

    asn_list = cJSON_GetObjectItem(root, "as_info_list");
    g_fc_server.asns_num = cJSON_GetArraySize(asn_list);

    for (i = 0; i < g_fc_server.asns_num; ++i)
    {
        memset(&meta, 0, sizeof(meta));
        elem = cJSON_GetArrayItem(asn_list, i);
        if (g_fc_server.log_level >= FC_LOG_LEVEL_DEBUG)
        {
            fc_cjson_print(elem);
        }

        asn = cJSON_GetObjectItem(elem, "asn");
        FC_ASSERT_RETP(asn);
        cert = cJSON_GetObjectItem(elem, "cert");
        FC_ASSERT_RETP(cert);
        nics = cJSON_GetObjectItem(elem, "nics");
        FC_ASSERT_RETP(nics);
        acs = cJSON_GetObjectItem(elem, "acs");
        FC_ASSERT_RETP(acs);

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
        FC_MEM_FREE(fpath);

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
            TXTRED("insert failed\n");
            return -1;
        }
        printf("====================================================\n");
    }

    return 0;
}

int fc_read_config(void)
{
    cJSON *root = NULL;

    root = fc_cjson_root_ptr(g_fc_server.config_fname);
    FC_ASSERT_RETP(root);

    // optional configurations which have default values
    fc_json_read_fc_db_fname(root);
    fc_json_read_listen_port(root);
    fc_json_read_hash_algo_id(root);
    fc_json_read_log_mode(root);
    fc_json_read_clear_fc_db(root);
    fc_json_read_dp_mode(root); // none, linux(nftables), h3c, vpp

    // necessary configurations
    fc_json_read_local_asn(root);
    fc_json_read_certs_location(root);
    fc_json_read_private_key(root);
    fc_json_read_router_info_list(root);
    fc_json_read_as_info_list(root);

    cJSON_Delete(root);

    return 0;
}
