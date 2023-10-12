/********************************************************************************
 * File Name:    bgp_fc.c
 * Author:       basilguo@163.com
 * Created Time: 2023-09-25 10:09:53
 * Description:
 ********************************************************************************/

// #include "bgpd/bgpd.h"
#include "bgpd/bgp_fc.h"

ncs_ctx_t *fc_bgpd_ctx = NULL;
FC_server_t g_fc_server = {0};

/* JSON UTILS */
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

    static void
fc_cjson_print(const cJSON* root)
{
    char *output = cJSON_Print(root);
    printf("%s\n", output);
    free(output);
}

    static cJSON *
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

    int
fc_read_asn_ips()
{
    cJSON *root = NULL, *asn_list = NULL;
    cJSON *elem = NULL, *asn = NULL,  *acs = NULL;
    cJSON *ipv4 = NULL, *ipv6 = NULL, *ip4s = NULL, *ip6s = NULL;
    cJSON *addr = NULL, *prefix_len = NULL;
    FC_node_as_t meta = {0};
    FC_ht_node_as_t *node = NULL;
    int size = 0, i = 0, j = 0, addr_num = 0, ret = 0;

    root = fc_cjson_root_ptr(g_fc_server.fname);
    assert(root);
    asn_list = cJSON_GetObjectItem(root, "asn_list");
    assert(asn_list);
    size = cJSON_GetArraySize(asn_list);
    g_fc_server.asns_num = size;

    for (i=0; i<size; ++i)
    {
        elem = cJSON_GetArrayItem(asn_list, i);
        // fc_cjson_print(elem);
        asn = cJSON_GetObjectItem(elem, "asn");
        acs = cJSON_GetObjectItem(elem, "acs");
        ip4s = cJSON_GetObjectItem(elem, "ip4s");
        ip6s = cJSON_GetObjectItem(elem, "ip6s");
        ipv4 = cJSON_GetObjectItem(acs, "ipv4");
        ipv6 = cJSON_GetObjectItem(acs, "ipv6");

        /*
           printf("asn: %d, g_fc_server.local_asn: %d\n",
           asn->valueint, g_fc_server.local_asn);

           if (asn->valueint == g_fc_server.local_asn)
           {
           memcpy(g_fc_server.ipv4, ipv4->valuestring,
           strlen(ipv4->valuestring));
           memcpy(g_fc_server.ipv6, ipv6->valuestring,
           strlen(ipv6->valuestring));
           }
           */

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
        g_fc_server.asns[i] = meta.asn;
        node = htbl_meta_insert(&g_fc_server.ht, &meta, &ret);
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
fc_print_asn_ips()
{
    printf("=====================================================\n");
    int i=0, j=0;
    FC_node_as_t meta;
    FC_ht_node_as_t *node;
    char ipstr[INET6_ADDRSTRLEN] = {0};
    htbl_ctx_t *ht = &g_fc_server.ht;

    printf("asns_num: %d\n", g_fc_server.asns_num);
    for (i=0; i<g_fc_server.asns_num; ++i)
    {
        meta.asn = g_fc_server.asns[i];
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
                        ipstr, (socklen_t)sizeof(struct sockaddr_in));
                printf("    ipv4: %s/%d\n",
                        ipstr, node->ap.prefix.ip4s[j].prefix_length);
            }
            for (j=0; j<node->ap.prefix.ip6s_num; ++j)
            {
                inet_ntop(AF_INET6, &node->ap.prefix.ip6s[j].ip,
                        ipstr, (socklen_t)sizeof(struct sockaddr_in));
                printf("    ipv6: %s/%d\n",
                        ipstr, node->ap.prefix.ip6s[j].prefix_length);
            }

            // htbl_node_drop(ht, node);
        }

        /*
           if (node)
           {
           htbl_node_delete(ht, node);
           node = NULL;
           }
           */
    }
    printf("=====================================================\n");
}

/* HASHTABLE UTILS */
void *
fc_as_node_create(void)
{
    FC_ht_node_as_t *node = malloc(sizeof(FC_ht_node_as_t));
    return node;
}

int
fc_as_node_destroy(void *node)
{
    free(node);
    return 0;
}

int
fc_as_node_display(void *node)
{
    char ipstr[INET6_ADDRSTRLEN] = {0};
    int i = 0;
    FC_ht_node_as_t *node_as = (FC_ht_node_as_t *) node;

    printf("asn: %d\n", node_as->asn);
    printf("  acs:\n");
    printf("    ipv4: %s\n", node_as->ap.acs.ipv4);
    printf("    ipv6: %s\n", node_as->ap.acs.ipv6);
    printf("  prefix:\n");
    for (i=0; i<node_as->ap.prefix.ip4s_num; ++i)
    {
        inet_ntop(AF_INET, &node_as->ap.prefix.ip4s[i].ip,
                ipstr, (socklen_t)sizeof(ipstr));
        printf("    ipv4: %s/%d\n",
                ipstr, node_as->ap.prefix.ip4s[i].prefix_length);
    }
    for (i=0; i<node_as->ap.prefix.ip6s_num; ++i)
    {
        inet_ntop(AF_INET6, &node_as->ap.prefix.ip6s[i].ip,
                ipstr, (socklen_t)sizeof(ipstr));
        printf("    ipv6: %s/%d\n",
                ipstr, node_as->ap.prefix.ip6s[i].prefix_length);
    }

    return 0;
}

static int
fc_as_hash(u32 asn)
{
    int ret = jhash_1word(asn, 0x19841128);
    // printf("ret : %d\n", ret);
    return ret;
}

int
fc_as_node_hash(void *node)
{
    FC_ht_node_as_t *node_as = (FC_ht_node_as_t *) node;
    return fc_as_hash(node_as->asn);
}

int
fc_as_meta_hash(void *meta)
{
    FC_node_as_t *meta_as = (FC_node_as_t *)meta;
    return fc_as_hash(meta_as->asn);
}

int
fc_as_meta_cmp(void *base, void *meta)
{
    FC_ht_node_as_t *node_as = (FC_ht_node_as_t *)base;
    FC_node_as_t *meta_as = (FC_node_as_t *)meta;

    return !!(node_as->asn != meta_as->asn);
}

int
fc_as_meta_save(void *base, void *meta)
{
    FC_ht_node_as_t *node_as = (FC_ht_node_as_t *)base;
    FC_node_as_t *meta_as = (FC_node_as_t *)meta;

    node_as->asn = meta_as->asn;
    memcpy(&node_as->ap, &meta_as->ap, sizeof(FC_asn_ip_t));

    return 0;
}

static htbl_ops_t g_htbl_ops = {
    .node_create_func = fc_as_node_create,
    .node_destroy_func = fc_as_node_destroy,
    .node_display_func = fc_as_node_display,
    .node_hash_func = fc_as_node_hash,
    .meta_hash_func = fc_as_meta_hash,
    .meta_cmp_func = fc_as_meta_cmp,
    .meta_save_func = fc_as_meta_save,
};

// 这里需要注意到是，htbl_ops需要是在ht之后不能销毁的
// 所以只能使用g_htbl_ops这种用法了
int fc_hashtable_create(htbl_ctx_t *ht)
{
    int ret = 0;
    ht->bucketcnt = FCSRV_MAX_LINK_AS;
    ht->ops = &g_htbl_ops;

    ret = htbl_init(ht);
    FC_ASSERT_RET(ret);
    /*
       printf("htbl_init return %d ptr size %d spinlock size %d atomic size %d hlist size %d rwlock size %d hnode size %d node size %d\n",
       ret, (int)sizeof(void *), (int)sizeof(spinlock_t), (int)sizeof(atomic_t),
       (int)sizeof(htbl_hlist_t), (int)sizeof(rwlock_t),
       (int)sizeof(htbl_node_t), (int)sizeof(FC_ht_node_as_t));
       */

    return 0;
}

int
fc_hashtable_destroy(htbl_ctx_t *ht)
{
    if (ht)
    {
        htbl_fini(ht);
    }
    return 0;
}


/* SQLITE3 DATABASE UTILS */
/* Open database */
int
fc_db_open(sqlite3 **db, const char *dbname)
{
    if (sqlite3_open(dbname, db) != SQLITE_OK)
    {
        DIAG_ERROR("Can't open database: %s\n", sqlite3_errmsg(*db));
        exit(0);
    }
    else
    {
        DIAG_DEBUG("Opened database successfully\n");
    }

    return 0;
}

int
fc_db_store_bm_handler(void *data, int argc, char **argv,
        char **az_col_name)
{
    return 0;
}

int
fc_db_select_bm_handler(void *data, int argc, char **argv,
        char **az_col_name)
{
    return 0;
}

/* Execute SQL statement */
int
fc_db_exec(sqlite3 *db, const char *sql,
        int (*cb)(void *data, int argc, char **argv, char **az_col_name),
        void *data)
{
    char *zErrMsg = 0;
    int rc;
    rc = sqlite3_exec(db, sql, cb, data, &zErrMsg);
    if (rc != SQLITE_OK)
    {
        DIAG_ERROR("SQL error: %s\n", zErrMsg);
        sqlite3_free(zErrMsg);
    }
    else
    {
        DIAG_DEBUG("Operation done successfully\n");
    }

    return 0;
}

/* Close DB */
int
fc_db_close(sqlite3 *db)
{
    sqlite3_close(db);
    return 0;
}

void
fc_init_db(sqlite3 **db)
{
    char sql[BUFSIZ];

    fc_db_open(db, FC_DB_NAME);
    bzero(sql, BUFSIZ);
    sprintf(sql, "DROP TABLE IF EXISTS fcs;");
    DIAG_DEBUG("sql: %s\n", sql);
    fc_db_exec(*db, sql, NULL, NULL);

    bzero(sql, BUFSIZ);
    sprintf(sql, "CREATE TABLE fcs("
            "ipversion INT NOT NULL,"
            "type INT NOT NULL,"
            "action INT NOT NULL,"
            "fc_num INT NOT NULL,"
            "src_ip_num INT NOT NULL,"
            "dst_ip_num INT NOT NULL,"
            "siglen INT NOT NULL,"
            "local_asn INT NOT NULL,"
            "version INT NOT NULL,"
            "subversion INT NOT NULL,"
            "src_ip CHAR(1024) NOT NULL,"
            "dst_ip CHAR(1024) NOT NULL,"
            "fclist CHAR(2048) NOT NULL,"
            "ski CHAR(20) NOT NULL,"
            "signature CHAR(1024) NOT NULL)"
           );
    DIAG_DEBUG("sql: %s\n", sql);
    fc_db_exec(*db, sql, NULL, NULL);
    // bzero(sql, 1024);
    // sprintf(sql, "DELETE FROM relation WHERE asn = %u", asn);
    // fc_db_exec(*db, sql, NULL, NULL);
}

/* SIGN/VERIFY UTILS */
    int
fc_base64_encode(const unsigned char *msg, size_t length, char *b64msg)
{
    BIO *bio, *b64;
    BUF_MEM *buff;
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    // ignore new lines - write everything in one line
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, msg, length);
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &buff);
    BIO_set_close(bio, BIO_NOCLOSE);
    BIO_free_all(bio);

    memcpy(b64msg, (*buff).data, strlen((*buff).data));
    printf("msg: %s\nb64msg: %s\ndata: %s\n",
            msg, b64msg, (*buff).data);

    return 0;
}

    static size_t inline
fc_calc_decode_len(const char *b64msg)
{
    size_t len = strlen(b64msg);
    size_t padding = 0;

    if (b64msg[len-1] == '=' && b64msg[len-2] == '=')
        padding = 2;
    else if (b64msg[len-1] == '=')
        padding = 1;

    return (len * 3) / 4 - padding;
}

    int
fc_base64_decode(const char *b64msg, unsigned char **msg, size_t *length)
{
    BIO *bio, *b64;
    int decode_len = fc_calc_decode_len(b64msg);

    *msg = (unsigned char *) malloc(decode_len + 1);
    (*msg)[decode_len] = '\0';

    bio = BIO_new_mem_buf(b64msg, -1);
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    *length = BIO_read(bio, *msg, strlen(b64msg));
    if (*length != decode_len)
    {
        DIAG_ERROR("error b64 decode length\n");
        return -1;
    }

    BIO_free_all(bio);

    return 0;
}

    static int
fc_sha256_encode(const char *const msg, unsigned char *digest,
        unsigned int *digest_len)
{
    int i = 0, ret = 1;
    EVP_MD *md = NULL;
    EVP_MD_CTX *mdctx = NULL;

    /* Create a context for the digest operation */
    if ((mdctx = EVP_MD_CTX_new()) == NULL)
    {
        goto error;
    }

    /*
     * Fetch the SHA256 algorithm implementation for doing the digest. We're        * using the "default" library context here (first NULL parameter), and
     * we're not supplying any particular search criteria for our SHA256
     * implementation (second NULL parameter). Any SHA256 implementation will
     * do.                                                                          * In a larger application this fetch would just be done once, and could
     * be used for multiple calls to other operations such as EVP_DigestInit_ex().                                                                                 */
    if ((md = EVP_MD_fetch(NULL, "SHA256", NULL)) == NULL)                         {
        goto error;
    }


    /* Initialise the digest operation */
    if (!EVP_DigestInit_ex(mdctx, md, NULL))
    {
        goto error;
    }

    /*
     * Pass the message to be digested. This can be passed in over multiple
     * EVP_DigestUpdate calls if necessary
     */
    if (!EVP_DigestUpdate(mdctx, msg, strlen(msg)))
    {
        goto error;
    }

    /* Allocate the output buffer */
    /* digest = OPENSSL_malloc(EVP_MD_get_size(sha256));
     * if (digest == NULL)
     * {
     *  goto err;
     * }
     **/
    /* Allocate the output buffer */
    if (!EVP_DigestFinal_ex(mdctx, digest, digest_len))
    {
        goto error;
    }

    DIAG_DEBUG("Digest_len is : %u, Digest is: ", *digest_len);
    for (i = 0; i < *digest_len; i++)
        DIAG_DEBUG("%02x", digest[i]);
    DIAG_DEBUG("\n");

error:
    /* Clean up all the resources we allocated */
    EVP_MD_free(md);
    EVP_MD_CTX_free(mdctx);
    if (ret != 0)
    {
        ERR_print_errors_fp(stderr);
    }

    return ret;
}

    int
fc_read_eckey_from_file(int is_pub_key, EC_KEY **pkey)
{
    const char *public_key_fname = "assets/eccpri256.pem";
    const char *private_key_fname = "assets/eccpri256.key";
    FILE *fp = NULL;

    if (is_pub_key)
    {
        if ((fp = fopen(public_key_fname, "rb")) == NULL)
        {
            perror("fopen()");
            return -1;
        }

        *pkey = PEM_read_EC_PUBKEY(fp, NULL, NULL, NULL);
    } else {
        if ((fp = fopen(private_key_fname, "rb")) == NULL)
        {
            perror("fopen()");
            return -1;
        }
        *pkey = PEM_read_ECPrivateKey(fp, NULL, NULL, NULL);
    }
    fclose(fp);

    return 0;
}

    int
fc_ecdsa_sign(EC_KEY *prikey, const char *const msg,
        unsigned char **sigbuff, unsigned int *siglen)
{
    unsigned char digest[EVP_MAX_MD_SIZE] = {0};
    unsigned int digestlen = 0;
    unsigned int keylen = 0;
    int ret = 0;

    fc_sha256_encode(msg, digest, &digestlen);
    keylen = ECDSA_size(prikey);
    *sigbuff = OPENSSL_malloc(keylen);
    ret = ECDSA_sign(0, digest, digestlen, *sigbuff, siglen, prikey);

    printf("sig len: %u\nsignature: ", *siglen);
    for (int i=0; i<*siglen; ++i)
    {
        printf("%02X", (*sigbuff)[i]);
    }
    printf("\n");

    return 0;
}

    int
fc_ecdsa_verify(EC_KEY *pubkey, const char *const msg,
        const unsigned char *sigbuff, unsigned int siglen)
{
    unsigned char digest[EVP_MAX_MD_SIZE] = {0};
    unsigned int digestlen = 0;
    int ret = 0;

    fc_sha256_encode(msg, digest, &digestlen);
    ret = ECDSA_verify(0, digest, digestlen, sigbuff, siglen, pubkey);
    /*
       if (ret == 1)
       {
       printf("verify ok\n");
       }
       else if (ret == 0)
       {
       printf("verify failed\n");
       } else
       {
       printf("error\n");
       }
       */

    return ret;
}

    int
fc_init_crypto_env(FC_server_t *fcserver)
{
    fc_read_eckey_from_file(1, &fcserver->pubkey);
    fc_read_eckey_from_file(0, &fcserver->prikey);

    return 0;
}

/* FC SERVER UTILS */
    void
fc_server_signal_handler(int sig_num)
{
    if (sig_num == SIGINT)
    {
        if (fc_bgpd_ctx)
        {
            ncs_manager_stop(fc_bgpd_ctx);
            ncs_destroy(fc_bgpd_ctx);
            fc_bgpd_ctx = NULL;
        }
        /*
           if (bc_ctx)
           {
           ncs_manager_stop(bc_ctx);
           ncs_destroy(bc_ctx);
           bc_ctx = NULL;
           }
           */
        fc_server_destroy();
        printf("bye bye!\n");
        exit(0);
    }
}

    int
fc_server_create()
{
    FC_node_as_t meta;
    FC_ht_node_as_t *node;

    fc_init_db(&g_fc_server.db);

    meta.asn = g_fc_server.local_asn;
    node = htbl_meta_find(&g_fc_server.ht, &meta);

    if (node)
    {
        printf("asn: %d\n", node->asn);
        printf("  acs:\n");
        printf("    ipv4: %s\n", node->ap.acs.ipv4);
        printf("    ipv6: %s\n", node->ap.acs.ipv6);

        FC_acs_t *acs = &node->ap.acs;

        if ((fc_bgpd_ctx = ncs_create("bgpd", TCP_PROTO)) == NULL)
        {
            DIAG_ERROR("create bgpd ncs failed\n");
            exit(-ENOMEM);
        }

        // ncs_setup(fc_bgpd_ctx, acs->ipv4, FC_PORT, NULL, 0);
        ncs_setup(fc_bgpd_ctx, "0.0.0.0", FC_PORT, NULL, 0);
        ncs_timeout(fc_bgpd_ctx, 10, -1);
        ncs_setkeepalive(fc_bgpd_ctx, 10);
        ncs_server_enable(fc_bgpd_ctx);
        ncs_server_register(fc_bgpd_ctx, fc_server_handler);
        ncs_manager_start(fc_bgpd_ctx);
    }

    return 0;
}

    int
fc_server_destroy()
{
    printf("Close db\n");
    fc_db_close(g_fc_server.db);
    printf("Destroy Hashtable\n");
    fc_hashtable_destroy(&g_fc_server.ht);
    printf("Close diag\n");
    diag_fini();

    return 0;
}

    static int
fc_bm_sent_to_peer(const char *addr, const FC_msg_bm_t *bm,
        char *buffer, int bufferlen)
{
    int ret = 0;
    int sockfd = 0;
    int len = 0;
    struct sockaddr_in sockaddr;

    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        perror("socket()");
        return -1;
    }
    sockaddr.sin_family = AF_INET;
    sockaddr.sin_port = htons(FC_PORT);
    inet_pton(AF_INET, addr, &sockaddr.sin_addr);
    if ((ret = connect(sockfd, (struct sockaddr*)&sockaddr,
                    sizeof(sockaddr))) < 0)
    {
        perror("connect()");
        return -1;
    }

    while (len != bufferlen)
    {
        len = len + send(sockfd, buffer+len, bufferlen-len, 0);
        printf("len = %d, bufferlen = %d\n", len, bufferlen);
    }

    close(sockfd);

    return 0;
}

    static int
fc_bm_broadcast_to_peer(const FC_msg_bm_t *bm, char *buffer,
        int bufferlen)
{
    int i = 0;
    FC_node_as_t meta;

    for (i=0; i<bm->fc_num; ++i)
    {
        // TODO wether asn is in aspath
        meta.asn = bm->fclist[i].current_asn;
        FC_ht_node_as_t *node = htbl_meta_find(&g_fc_server.ht,
                &meta);
        if (node)
        {
            printf("sent to %d\n", node->asn);
            if (g_fc_server.local_asn != node->asn)
            {
                fc_bm_sent_to_peer(node->ap.acs.ipv4,
                        bm, buffer, bufferlen);
            }
        }
    }

    return 0;
}

    int
fc_db_write_bm(const FC_msg_bm_t *bm)
{
    char sql[BUFSIZ] = {0};
    // base64 encode
    char buff_src_ip[FC_BUFF_SIZE] = {0};
    char buff_dst_ip[FC_BUFF_SIZE] = {0};
    char buff_fclist[FC_BUFF_SIZE] = {0};
    char buff_ski[100] = {0};
    char buff_signature[FC_BUFF_SIZE] = {0};
    // char buff[BUFSIZ] = {0};
    int cur = 0, i = 0;
    socklen_t socklen;
    struct sockaddr_in *sin = NULL;
    struct sockaddr_in6 *sin6 = NULL;

    if (bm->ipversion == IPV4)
    {
        socklen = sizeof(struct sockaddr_in);
    } else if (bm->ipversion == IPV6)
    {
        socklen = sizeof(struct sockaddr_in6);
        DIAG_ERROR("THIS IS NOT supported: %d!\n", bm->ipversion);
        return 0;
    } else
    {
        DIAG_ERROR("THIS IS NOT supported: %d!\n", bm->ipversion);
        return -1;
    }

    // use , to split strings
    // base64 encode src_ip
    cur = 0;
    // memset(buff, 0, BUFSIZ);
    for (i=0; i<bm->src_ip_num; ++i)
    {
        if (bm->ipversion == IPV4)
        {
            sin = (struct sockaddr_in *)&(bm->src_ip[i].ip);
            inet_ntop(AF_INET, &sin->sin_addr, buff_src_ip+cur, socklen);
        } else {
            sin6 = (struct sockaddr_in6 *)&(bm->src_ip[i].ip);
            inet_ntop(AF_INET, &sin6->sin6_addr, buff_src_ip+cur, socklen);
        }
        cur += strlen(buff_src_ip+cur);
        snprintf(buff_src_ip+cur, FC_BUFF_SIZE, "/%d,",
                bm->src_ip[i].prefix_length);
        cur += strlen(buff_src_ip+cur);
        DIAG_DEBUG("src: %s\n", buff_src_ip);
    }

    // fc_base64_encode(buff, cur, buff_src_ip);

    // base64 encode dst_ip
    cur = 0;
    // memset(buff_dst_ip, 0, BUFSIZ);
    for (i=0; i<bm->dst_ip_num; ++i)
    {
        if (bm->ipversion == IPV4)
        {
            sin = (struct sockaddr_in *)&(bm->dst_ip[i].ip);
            inet_ntop(AF_INET, &sin->sin_addr, buff_dst_ip+cur, socklen);
        } else {
            sin6 = (struct sockaddr_in6 *)&(bm->dst_ip[i].ip);
            inet_ntop(AF_INET, &sin6->sin6_addr, buff_dst_ip+cur, socklen);
        }
        cur += strlen(buff_dst_ip+cur);
        snprintf(buff_dst_ip+cur, FC_BUFF_SIZE, "/%d,", bm->dst_ip[i].prefix_length);
        cur += strlen(buff_dst_ip+cur);
        DIAG_DEBUG("dst: %s\n", buff_dst_ip);
    }
    // fc_base64_encode(buff, cur, buff_dst_ip);

    // base64 encode fclist
    cur = 0;
    // memset(buff, 0, BUFSIZ);
    for (i=0; i<bm->fc_num; ++i)
    {
        snprintf(buff_fclist+cur, FC_BUFF_SIZE, "%08X-%08X-%08X-",
                bm->fclist[i].previous_asn,
                bm->fclist[i].current_asn,
                bm->fclist[i].nexthop_asn);
        cur += 8*3 + 3;
        for (int j=0; j<20; ++j)
        {
            snprintf(buff_fclist+cur, BUFSIZ, "%02X",
                    bm->fclist[i].ski[j]);
            cur += 2;
        }
        snprintf(buff_fclist+cur, FC_BUFF_SIZE, "-%02X-%02X-%04X-",
                bm->fclist[i].algo_id,
                bm->fclist[i].flags, bm->fclist[i].siglen);
        cur += 8 + 4;

        for (int j=0; j<bm->fclist[i].siglen; ++j)
        {
            snprintf(buff_fclist+cur, FC_BUFF_SIZE, "%02X",
                    bm->fclist[i].sig[j]);
            cur += 2;
        }
        snprintf(buff_fclist+cur, FC_BUFF_SIZE, ",");
        cur += 1;
        DIAG_DEBUG("curlen: %d, fclist: %s\n", cur, buff_fclist);
    }
    // fc_base64_encode(buff, cur, buff_fclist);

    /*
       DIAG_DEBUG("buff-srcip: %s\n", buff_src_ip);
       DIAG_DEBUG("buff-dstip: %s\n", buff_dst_ip);
       DIAG_DEBUG("buff-fclist: %s\n", buff_fclist);
       */

    // ski
    cur = 0;
    for (int j=0; j<20; ++j)
    {
        snprintf(buff_ski+cur, FC_BUFF_SIZE, "%02X",
                bm->fclist[i].ski[j]);
        cur += 2;
    }
    // signature
    for (int j = 0; j < bm->siglen; ++j)
    {
        snprintf(buff_signature+j*2, FC_BUFF_SIZE, "%02X",
                bm->signature[j]);
    }
    printf("signature: %s\n", buff_signature);
    snprintf(sql, BUFSIZ,
            "INSERT INTO fcs VALUES(%u, %u, %u, %u, %u, %u, %u, %u, %u, "
            "%u, '%s', '%s', '%s', '%s', '%s')",
            bm->ipversion, bm->type, bm->action, bm->fc_num,
            bm->src_ip_num, bm->dst_ip_num, bm->siglen, bm->local_asn,
            bm->version, bm->subversion, buff_src_ip, buff_dst_ip,
            buff_fclist, buff_ski, buff_signature);
    printf("SQL: %s\n", sql);
    fc_db_exec(g_fc_server.db, sql, fc_db_store_bm_handler, NULL);

    return 0;
}

    int
fc_server_pubkey_handler(const char *buff, int len)
{
    return 0;
}

    static int
fc_bm_verify_fc(FC_msg_bm_t *bm)
{
    char msg[BUFSIZ];
    int ret = 0;
    int msglen = 0;
    int i = 0, j = 0;
    struct sockaddr_in *ip4;
    struct sockaddr_in6 *ip6;

    for (i=0; i<bm->fc_num; ++i)
    {
        memset(msg, 0, BUFSIZ);
        msglen = 0;
        // hash(prev_asn, curr_asn, next_asn, dst_ip)
        // asn
        memcpy(msg + msglen, &(bm->fclist[i].previous_asn), sizeof(u32));
        msglen += sizeof(u32);
        memcpy(msg + msglen, &(bm->fclist[i].current_asn), sizeof(u32));
        msglen += sizeof(u32);
        memcpy(msg + msglen, &(bm->fclist[i].nexthop_asn), sizeof(u32));
        msglen += sizeof(u32);
        // dst_ip
        for (j=0; j<bm->dst_ip_num; ++j)
        {
            if (bm->ipversion == IPV4)
            {
                ip4 = (struct sockaddr_in*)&(bm->dst_ip[j].ip);
                memcpy(msg+msglen, &(ip4->sin_addr), IP4_LENGTH);
                msglen += IP4_LENGTH;
            } else {
                ip6 = (struct sockaddr_in6*)&(bm->dst_ip[j].ip);
                memcpy(msg+msglen, &(ip6->sin6_addr), IP6_LENGTH);
                msglen += IP6_LENGTH;
            }
            memcpy(msg+msglen, &bm->dst_ip[j].prefix_length, 1);
            msglen += 1;
        }
        ret = fc_ecdsa_verify(g_fc_server.pubkey, msg,
                bm->fclist[i].sig, bm->fclist[i].siglen);
        switch (ret)
        {
        case 1:
            printf("verify fc ok\n");
            break;
        case 0:
            printf("verify fc failed\n");
            break;
        default:
            printf("verify fc error\n");
            break;
        }
    }
    return 0;
}

// buff is starting from bm's ipversion
// msg_type: is broadcast msg
    int
fc_server_bm_handler(char *buffer, int bufferlen, int msg_type)
{
    // remove header
    char buff_new_msg[BUFSIZ] = {0};
    memcpy(buff_new_msg, buffer, bufferlen);
    char *buff = buff_new_msg + FC_HDR_GENERAL_LENGTH;

    u32 i = 0;
    FC_msg_bm_t bm = {0};
    int cur = 0;
    int cur_siglen_pos = 0;
    int ret = 0;
    int ip_len = 0;
    char msg[BUFSIZ] = {0};
    unsigned char *sigbuff = NULL;
    unsigned int sigbufflen = 0;

    if (buff[0] == IPV4) // ipv4
    {
        ip_len = IP4_LENGTH;
    } else if (buff[0] == IPV6) // ipv6
    {
        ip_len = IP6_LENGTH;
        DIAG_ERROR("Not supported now: %d\n", buff[0]);
        return 0;
    } else
    {
        DIAG_ERROR("Not supported now: %d\n", buff[0]);
    }

    memcpy(&bm.ipversion, buff, sizeof(u8));
    cur += sizeof(u8); // ipversion
    cur += sizeof(u8); // type
    cur += sizeof(u8); // action
    cur += sizeof(u8); // fc_num
    cur += sizeof(u8); // src_ip_num
    cur += sizeof(u8); // dst_ip_num
    cur_siglen_pos = cur;
    cur += sizeof(u16); // siglen
    cur += sizeof(u32); // local_asn
    cur += sizeof(u32); // version
    cur += sizeof(u32); // subversion
    memcpy(&bm, buff, cur);

    bm.siglen = ntohs(bm.siglen);
    bm.local_asn = ntohl(bm.local_asn);
    bm.version = ntohl(bm.version);
    bm.subversion = ntohl(bm.subversion);

    // src_ip
    for (i=0; i<bm.src_ip_num; ++i)
    {
        if (bm.ipversion == IPV4)
        {
            struct sockaddr_in* addr = &bm.src_ip[i].ip;
            memcpy(&(addr->sin_addr),
                    buff+cur, sizeof(struct in_addr));
        } else
        {
            struct sockaddr_in6* addr = &bm.src_ip[i].ip;
            memcpy(&(addr->sin6_addr),
                    buff+cur, sizeof(struct in6_addr));
        }
        memcpy(&bm.src_ip[i].prefix_length, buff+cur+ip_len, 1);
        cur += ip_len + 1;
    }

    // dst_ip
    for (i=0; i<bm.dst_ip_num; ++i)
    {
        if (bm.ipversion == IPV4)
        {
            struct sockaddr_in* addr = &bm.dst_ip[i].ip;
            memcpy(&(addr->sin_addr),
                    buff+cur, sizeof(struct in_addr));
        } else
        {
            struct sockaddr_in6* addr = &bm.dst_ip[i].ip;
            memcpy(&(addr->sin6_addr),
                    buff+cur, sizeof(struct in6_addr));
        }
        memcpy(&bm.dst_ip[i].prefix_length, buff+cur+ip_len, 1);
        cur += ip_len + 1;
    }

    // fclist
    int fc_fixlen = sizeof(u32) // prev asn
        +sizeof(u32) // curr asn
        +sizeof(u32) // next asn
        +sizeof(u8)*20 // ski
        +sizeof(u8)  // algo_id
        +sizeof(u8)  // flags
        +sizeof(u16); // siglen

    for (i=0; i<bm.fc_num; ++i)
    {
        memcpy(&bm.fclist[i], buff+cur, fc_fixlen);
        cur += fc_fixlen;
        bm.fclist[i].previous_asn = ntohl(bm.fclist[i].previous_asn);
        bm.fclist[i].current_asn = ntohl(bm.fclist[i].current_asn);
        bm.fclist[i].nexthop_asn = ntohl(bm.fclist[i].nexthop_asn);
        bm.fclist[i].siglen = ntohs(bm.fclist[i].siglen);
        memcpy(bm.fclist[i].sig, buff+cur, bm.fclist[i].siglen);
        cur += bm.fclist[i].siglen;
    }

    // TODO verify fc
    ret = fc_bm_verify_fc(&bm);
    FC_ASSERT_RET(ret);

    // TODO need read from g_fc_server.
    // ski -- for signature
    memset(bm.ski, 0, FC_SKI_LENGTH);

    // signature to be signed and verified
    memcpy(msg, buff, cur);

    if (msg_type == FC_MSG_BGPD)
    {
        // add signature for sending to peers
        fc_ecdsa_sign(g_fc_server.prikey, msg, &sigbuff, &sigbufflen);
        memcpy(buff+cur+FC_SKI_LENGTH, sigbuff, sigbufflen);
        bm.siglen = sigbufflen;

        sigbufflen = htons(sigbufflen);
        memcpy(&buff[cur_siglen_pos], &sigbufflen, sizeof(bm.siglen));
        memcpy(bm.signature, sigbuff, bm.siglen);
        OPENSSL_free(sigbuff);
    } else
    {
        // verify and remove signature
        memcpy(bm.signature, buff+cur+FC_SKI_LENGTH, bm.siglen);
        ret = fc_ecdsa_verify(g_fc_server.pubkey, msg,
                bm.signature, bm.siglen);
        switch (ret)
        {
        case 1:
            printf("verify sig ok\n");
            break;
        case 0:
            printf("verify sig failed\n");
            break;
        default:
            printf("verify sig error\n");
            break;
        }
    }

    // TODO
    // gen_acl(&bm);

    fc_db_write_bm(&bm);

    if (msg_type == FC_MSG_BGPD)
    {
        printf("broadcast to peers\n");
        buff_new_msg[0] = 3;  // bc msg
        fc_bm_broadcast_to_peer(&bm, buff_new_msg,
                FC_HDR_GENERAL_LENGTH+cur+FC_SKI_LENGTH+bm.siglen);
    }

    return 0;
}

    int
fc_server_handler(ncs_ctx_t *ctx)
{
    int len = 0;
    char buff[BUFSIZ];

    do
    {
        memset(buff, 0, BUFSIZ);
        len = ncs_server_recv(ctx, buff, BUFSIZ);
        DIAG_DEBUG("len = %d, received from %s:%d %s:%d %s:%s\n",
                len, ctx->remote_addr, ctx->remote_port,
                ctx->local_addr, ctx->local_port,
                ctx->server_peeraddr, ctx->client_peeraddr);
        if (len > 0)
        {
            switch (buff[0])
            {
            case 1: // pubkey
                DIAG_ERROR("Not support pubkey\n");
                // TODO length
                fc_server_pubkey_handler(buff, len);
                return 0;
            case 2: // bm
                // TODO length
                fc_server_bm_handler(buff, len, FC_MSG_BGPD);
                break;
            case 3: // broadcast msg
                // TODO length
                fc_server_bm_handler(buff, len, FC_MSG_BC);
                break;
            default:
                DIAG_ERROR("Not support %d\n", buff[0]);
                return -1;
            }
        }
    } while (0);

    ncs_client_stop(ctx);

    return 0;
}

    static void inline
fc_help()
{
    printf("\t-h                            print this message.\n");
    printf("\t-a                            specify local as number.\n");
    printf("\t-f <asnlist.json location>    specify the location of asnlist.json\n");
}

    static int inline
fc_parse_args(int argc, char *argv[])
{
    int ch = '\0';
    int specified_local_asn = 0;
    while ((ch = getopt(argc, argv, "hf:a:")) != -1)
    {
        switch (ch)
        {
        case 'h':
            fc_help();
            exit(EXIT_SUCCESS);
        case 'f':
            size_t fname_len = strlen(optarg);
            memcpy(g_fc_server.fname, optarg, fname_len);
            g_fc_server.fname[fname_len] = '\0';
            break;
        case 'a':
            g_fc_server.local_asn = (u32) atol(optarg);
            specified_local_asn = 1;
            break;

        default:
            printf("unknow option: %c\n", ch);
            fc_help();
            break;
        }
    }

    if (!g_fc_server.fname || strlen(g_fc_server.fname) == 0)
    {
        // fprintf(stderr, "MUST use -f to specify the asnlist.json\n");
        // exit(-1);
        char *pfname = "assets/asnlist.json";
        memcpy(g_fc_server.fname, pfname, strlen(pfname));
    }

    if (!specified_local_asn)
    {
        fprintf(stderr, "MUST use -a to specify the local as number.\n");
        exit(-1);
    }

    return 0;
}

int fc_main(int argc, char *argv[])
{
    fc_parse_args(argc, argv);
    diag_init("fc");
    fc_hashtable_create(&g_fc_server.ht);

    // ??SRC-IPASN-f??asnlist.jsonλ
    //     ??????bin/server??????
    fc_read_asn_ips();
    fc_print_asn_ips();
    // htbl_display(&g_fc_server.ht);

    fc_init_crypto_env(&g_fc_server);

    signal(SIGINT, fc_server_signal_handler);

    fc_server_create();

    while (1)
    {
        sleep(1);
    }

    // fcserver
    fc_server_destroy();

    return 0;
}

#ifdef TEST_MAIN
int main(int argc, char **args)
{
    fc_main(argc, args);

    return 0;
}
#endif


/* BGPD TO FCSERVER */

// afi_t in zebra.h
/*
    int
bgpfc_prefix_to_ip_hton_format(struct bgp_nlri *packet,
        char *buff, int *bufflen, int buffsize)
{
    afi_t afi = packet->afi;
    uint8_t *pnt = NULL, *lim = NULL;
    int psize;

    pnt = packet->nlri;
    lim = pnt + packet->length;
    *bufflen = 0;

    for (; pnt < lim && buffsize > *bufflen; pnt += psize)
    {
        psize = PSIZE(p.prefixlen);
        memcpy(buff + *bufflen, pnt+1, psize);
        if (afi == AFI_IP) // ipv4
        {
            *bufflen += 4;
        } else if (afi == AFI_IP6) // ipv6
        {
            *bufflen += 16;
        }
        buff[*bufflen] = *pnt; // prefixlength
        *bufflen += 1;
    }

    return *bufflen;
}

    int
bgpfc_send_packet_to_fcserver(char *buff, int bufflen)
{
    struct sockaddr_in sockaddr;
    int ret = 0;
    int len = 0;

    sockaddr.sin_family = AF_INET;
    sockaddr.sin_port = htons(23160);
    inet_pton(AF_INET, "127.0.0.1", &sockaddr.sin_addr);

    ret = connect(sockfd, (struct sockaddr *)&sockaddr, sizeof(sockaddr));
    if (ret < 0)
    {
        fprintf(stderr, "connect() error\n");
        perror("connect()");
        return -1;
    }

    while (len != bufflen)
    {
        len = len + send(sockfd, buff+len, bufflen-len, 0);
        printf("len = %d, total-length = %d\n", len, bufflen);
    }

    close(sockfd);

    return 0;
}
*/
