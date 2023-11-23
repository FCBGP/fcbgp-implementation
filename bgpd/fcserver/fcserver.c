/********************************************************************************
 * File Name:    fcserver.c
 * Author:       basilguo@163.com
 * Created Time: 2023-09-25 10:09:53
 * Description:
 ********************************************************************************/

#include "libdiag.h"
#include "fcserver.h"

const char g_fc_nft_chains[FC_NFT_FILTER_CHAIN_END][20]
    = {"input", "forward", "output"};
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

/**
 * If the user forgets to remove the tail '/', we need to properly accept that.
 * */
    static char*
fc_combine_path(const char* path, const char* filename)
{
    size_t path_len = strlen(path);
    size_t filename_len = strlen(filename);
    size_t combined_len = path_len + filename_len + 2;  // 2 for '/' and '\0'

    char* combined_path = (char*) malloc(combined_len);
    if (combined_path == NULL) {
        fprintf(stderr, "malloc for combined_path failed\n");
        return NULL;
    }

    memcpy(combined_path, path, strlen(path));
    if (path_len > 0 && path[path_len - 1] != '/') {
        strcat(combined_path, "/");
    }

    strcat(combined_path, filename);

    return combined_path;
}

    int
fc_read_asn_ips(void)
{
    cJSON *root = NULL, *asn_list = NULL, *certs_location = NULL, *prikey = NULL;
    cJSON *elem = NULL, *asn = NULL, *cert = NULL, *acs = NULL, *nics = NULL;
    cJSON *ipv4 = NULL, *ipv6 = NULL, *ifaddr = NULL, *ifname = NULL;
    cJSON *ifprefix = NULL;
    cJSON *addr = NULL, *prefix_len = NULL;
    FC_node_as_t meta = {0};
    FC_ht_node_as_t *node = NULL;
    int i = 0, j = 0, ret = 0;
    char *fpath = NULL;

    root = fc_cjson_root_ptr(g_fc_server.asnlist_fname);
    // local asn
    elem = cJSON_GetObjectItem(root, "local_asn");
    g_fc_server.local_asn = (u32) elem->valueint;
    // certs location
    certs_location = cJSON_GetObjectItem(root, "certs_location");
    memcpy(g_fc_server.certs_location, certs_location->valuestring,
            strlen(certs_location->valuestring));
    // private key
    prikey = cJSON_GetObjectItem(root, "private_key");
    memcpy(g_fc_server.prikey_fname, prikey->valuestring, strlen(prikey->valuestring));
    // as list
    asn_list = cJSON_GetObjectItem(root, "as_info_list");
    g_fc_server.asns_num = cJSON_GetArraySize(asn_list);
    for (i=0; i<g_fc_server.asns_num; ++i)
    {
        elem = cJSON_GetArrayItem(asn_list, i);
        fc_cjson_print(elem);
        asn = cJSON_GetObjectItem(elem, "asn");
        cert = cJSON_GetObjectItem(elem, "cert");
        nics = cJSON_GetObjectItem(elem, "nics");
        acs = cJSON_GetObjectItem(elem, "acs");
        ipv4 = cJSON_GetObjectItem(acs, "ipv4");
        ipv6 = cJSON_GetObjectItem(acs, "ipv6");

        // asn
        meta.asn = asn->valueint;

        // cert
        memcpy(meta.cert, cert->valuestring, strlen(cert->valuestring));
        fpath = fc_combine_path(g_fc_server.certs_location, meta.cert);
        fc_get_ecpubkey_and_ski(meta.asn, fpath, &meta.pubkey, meta.ski);
        free(fpath);
        fpath = NULL;

        // nics
        g_fc_server.nics_num = cJSON_GetArraySize(nics);
        for (j=0; j<g_fc_server.nics_num; ++j)
        {
            elem = cJSON_GetArrayItem(nics, j);
            memcpy(g_fc_server.nics[j],
                    elem->valuestring, strlen(elem->valuestring));
        }

        // acs ipv4 address
        meta.acs.ipv4_num = cJSON_GetArraySize(ipv4);
        for (j=0; j<meta.acs.ipv4_num; ++j)
        {
            elem = cJSON_GetArrayItem(ipv4, j);
            ifaddr = cJSON_GetObjectItem(elem, "ifaddr");
            ifprefix = cJSON_GetObjectItem(elem, "ifprefix");
            meta.acs.ipv4[j].ifprefix = ifprefix->valueint;
            ifname = cJSON_GetObjectItem(elem, "ifname");
            memcpy(meta.acs.ipv4[j].ifaddr, ifaddr->valuestring,
                    strlen(ifaddr->valuestring));
            memcpy(meta.acs.ipv4[j].ifname, ifname->valuestring,
                    strlen(ifname->valuestring));
        }

        // acs ipv6 address
        meta.acs.ipv6_num = cJSON_GetArraySize(ipv6);
        for (j=0; j<meta.acs.ipv6_num; ++j)
        {
            elem = cJSON_GetArrayItem(ipv6, j);
            ifaddr = cJSON_GetObjectItem(elem, "ifaddr");
            ifprefix = cJSON_GetObjectItem(elem, "ifprefix");
            meta.acs.ipv6[j].ifprefix = ifprefix->valueint;
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
            fprintf(stderr, "insert failed\n");
            return -1;
        }
        printf("====================================================================\n");
    }

    cJSON_Delete(root);

    return 0;
}

/* HASHTABLE UTILS */
    static void *
fc_as_node_create(void)
{
    FC_ht_node_as_t *node = malloc(sizeof(FC_ht_node_as_t));
    memset(node, 0, sizeof(FC_ht_node_as_t));
    return node;
}

    static int
fc_as_node_destroy(void *node)
{
    FC_ht_node_as_t *node_as = (FC_ht_node_as_t *)node;
    EC_KEY_free(node_as->pubkey);
    free(node_as);
    return 0;
}

    static int
fc_as_node_display(void *node)
{
    char ipstr[INET6_ADDRSTRLEN] = {0};
    int i = 0;
    FC_ht_node_as_t *node_as = (FC_ht_node_as_t *) node;

    printf("asn: %d\n", node_as->asn);
    printf(" cert: %s\n", node_as->cert);
    printf("  acs:\n");
    printf("    ipv4:\n");
    for (i=0; i<node_as->acs.ipv4_num; ++i)
    {
        printf("      ifname: %s\n", node_as->acs.ipv4[i].ifname);
        printf("      ifprefix: %d\n", node_as->acs.ipv4[i].ifprefix);
        printf("      ifaddr: %s\n", node_as->acs.ipv4[i].ifaddr);
    }
    printf("    ipv6:\n");
    for (i=0; i<node_as->acs.ipv6_num; ++i)
    {
        printf("      ifname: %s\n", node_as->acs.ipv6[i].ifname);
        printf("      ifprefix: %d\n", node_as->acs.ipv4[i].ifprefix);
        printf("      ifaddr: %s\n", node_as->acs.ipv6[i].ifaddr);
    }

    return 0;
}

    static u32
fc_as_hash(u32 asn)
{
    u32 ret = jhash_1word(asn, 0xdeadbeef);
    // printf("ret : %d\n", ret);
    return ret;
}

    static int
fc_as_node_hash(void *node)
{
    FC_ht_node_as_t *node_as = (FC_ht_node_as_t *) node;
    return fc_as_hash(node_as->asn);
}

    static int
fc_as_meta_hash(void *meta)
{
    FC_node_as_t *meta_as = (FC_node_as_t *)meta;
    return fc_as_hash(meta_as->asn);
}

    static int
fc_as_meta_cmp(void *base, void *meta)
{
    FC_ht_node_as_t *node_as = (FC_ht_node_as_t *)base;
    FC_node_as_t *meta_as = (FC_node_as_t *)meta;

    return !!(node_as->asn != meta_as->asn);
}

    static int
fc_as_meta_save(void *base, void *meta)
{
    FC_ht_node_as_t *node_as = (FC_ht_node_as_t *)base;
    FC_node_as_t *meta_as = (FC_node_as_t *)meta;

    node_as->asn = meta_as->asn;
    node_as->pubkey = meta_as->pubkey;
    memcpy(&node_as->acs, &meta_as->acs, sizeof(FC_acs_t));
    memcpy(node_as->cert, meta_as->cert, strlen(meta_as->cert));
    memcpy(node_as->ski, meta_as->ski, FC_SKI_LENGTH);

    return 0;
}

htbl_ops_t g_fc_htbl_as_ops = {
    .node_create_func = fc_as_node_create,
    .node_destroy_func = fc_as_node_destroy,
    .node_display_func = fc_as_node_display,
    .node_hash_func = fc_as_node_hash,
    .meta_hash_func = fc_as_meta_hash,
    .meta_cmp_func = fc_as_meta_cmp,
    .meta_save_func = fc_as_meta_save,
};

    static void *
fc_prefix_node_create(void)
{
    FC_ht_node_prefix_t *node = malloc(sizeof(FC_ht_node_prefix_t));
    node->fcs = malloc(sizeof(FC_t) * FC_MAX_SIZE);
    return node;
}

    static int
fc_prefix_node_destroy(void *node)
{
    FC_ht_node_prefix_t *node_prefix = (FC_ht_node_prefix_t *)node;
    free(node_prefix->fcs);
    free(node_prefix);

    return 0;
}

    static int
fc_prefix_hash(struct prefix *prefix)
{
    int i = 0;
    int ret = 0;

    ret = jhash_2words(prefix->family, prefix->prefixlen, 0xdeadbeef);

    for (i=0; i<4; ++i)
        ret = jhash_2words(ret, prefix->u.val32[i], 0xdeadbeef);

    return ret;
}

    static int
fc_prefix_node_hash(void *node)
{
    FC_ht_node_prefix_t *node_prefix = (FC_ht_node_prefix_t *) node;
    return fc_prefix_hash(&node_prefix->ipprefix);
}

    static int
fc_prefix_meta_hash(void *meta)
{
    FCList_t *meta_prefix = (FCList_t *)meta;
    return fc_prefix_hash(&meta_prefix->ipprefix);
}

    static int
fc_prefix_meta_cmp(void *base, void *meta)
{
    FC_ht_node_prefix_t *node_prefix = (FC_ht_node_prefix_t *)base;
    FCList_t *meta_prefix = (FCList_t *)meta;

    int ret = 0; // 0 for equal and 1 for inequal
    int i = 0;

    if (node_prefix->ipprefix.family == meta_prefix->ipprefix.family)
    {
        if (node_prefix->ipprefix.prefixlen == meta_prefix->ipprefix.prefixlen)
        {
            for (i=0; i<4; ++i)
            {
                if (node_prefix->ipprefix.u.val32[i]
                        != meta_prefix->ipprefix.u.val32[i])
                {
                    ret = 1;
                    break;
                }
            }
            return ret;
        }
    }

    return ret;
}

    static int
fc_prefix_meta_save(void *base, void *meta)
{
    FC_ht_node_prefix_t *node_prefix = (FC_ht_node_prefix_t *)base;
    FCList_t *meta_prefix = (FCList_t *)meta;

    node_prefix->size = meta_prefix->size;
    node_prefix->length = meta_prefix->length;
    node_prefix->fcs = meta_prefix->fcs;
    memcpy(&node_prefix->ipprefix, &meta_prefix->ipprefix, sizeof(struct prefix));

    return 0;
}

    static int
fc_prefix_node_display(void *node)
{
    return 0;
}

htbl_ops_t g_fc_htbl_prefix_ops = {
    .node_create_func = fc_prefix_node_create,
    .node_destroy_func = fc_prefix_node_destroy,
    .node_display_func = fc_prefix_node_display,
    .node_hash_func = fc_prefix_node_hash,
    .meta_hash_func = fc_prefix_meta_hash,
    .meta_cmp_func = fc_prefix_meta_cmp,
    .meta_save_func = fc_prefix_meta_save,
};

// 这里需要注意到是，htbl_ops需要是在ht之后不能销毁的
// 所以只能使用g_htbl_ops这种用法了
int fc_hashtable_create(htbl_ctx_t *ht, htbl_ops_t *ops)
{
    int ret = 0;
    ht->bucketcnt = FCSRV_HTBL_BUCKETS_SIZE;
    ht->ops = ops;

    ret = htbl_init(ht);
    FC_ASSERT_RET(ret);
    /*
       printf("htbl_init return %d ptr size %d spinlock size %d atomic size %d hlist size %d rwlock size %d hnode size %d node size %d",
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
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(*db));
        exit(0);
    }
    else
    {
        printf("Opened database successfully\n");
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
        fprintf(stderr, "SQL error: %s\n", zErrMsg);
        sqlite3_free(zErrMsg);
    }
    else
    {
        printf("Operation done successfully\n");
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
    printf("sql: %s\n", sql);
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
    printf("sql: %s\n", sql);
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
    printf("msg: %s, b64msg: %s, data: %s\n",
            msg, b64msg, (*buff).data);

    return 0;
}

    static inline size_t
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
    size_t decode_len = fc_calc_decode_len(b64msg);

    *msg = (unsigned char *) malloc(decode_len + 1);
    (*msg)[decode_len] = '\0';

    bio = BIO_new_mem_buf(b64msg, -1);
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    *length = BIO_read(bio, *msg, strlen(b64msg));
    if (*length != decode_len)
    {
        printf("error b64 decode length\n");
        return -1;
    }

    BIO_free_all(bio);

    return 0;
}

    static int
fc_sha256_encode(const char *const msg, int msglen, unsigned char *digest,
        unsigned int *digest_len)
{
    int ret = 1;
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
    if (!EVP_DigestUpdate(mdctx, msg, msglen))
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

    /*
       printf("Digest_len is : %u, Digest is: ", *digest_len);
       for (i = 0; i < (int)*digest_len; i++)
       {
       printf("%02x", digest[i]);
       }
       printf("\n");
       */

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
fc_get_ecpubkey_and_ski(u32 asn, const char *fpath, EC_KEY **ecpubkey, u8 *ecski)
{
    FILE *fp = NULL;
    X509 *cert = NULL;
    EVP_PKEY *pubkey = NULL;
    BIO *bio_in = NULL;
    BIO *bio_out = NULL;
    const ASN1_OCTET_STRING *ski = NULL;

    if ((bio_in = BIO_new_file(fpath, "r")) == NULL)
    {
        fprintf(stderr, "Couldn't read certificate file\n");
        return -1;
    }

    if ((bio_out = BIO_new_fp(stdout, BIO_NOCLOSE)) == NULL)
    {
        fprintf(stderr, "Couldn't create bio_out\n");
        return -1;
    }

    if ((cert = X509_new()) == NULL)
    {
        fprintf(stderr, "X509_new() error\n");
        return -1;
    }

    if (PEM_read_bio_X509(bio_in, &cert, 0, NULL) == NULL)
    {
        fprintf(stderr, "Couldn't read public key from certificate file\n");
        return -1;
    }

    if ((ski = X509_get0_subject_key_id(cert)) != NULL)
    {
        ecski = (u8 *)ski->data;
        printf("ASN: %u, Subject Key Identifier (SKI): ", asn);
        for (int i = 0; i < ski->length; i++) {
            printf("%02X", ecski[i]);
        }
        printf("\n");
    }

    if ((pubkey = X509_get_pubkey(cert)) != NULL)
    {
        printf("ASN: %u, pubkey: ", asn);
        EVP_PKEY_print_public(bio_out, pubkey, 0, NULL);
    }

    ecpubkey = EVP_PKEY_get1_EC_KEY(pubkey);

    EVP_PKEY_free(pubkey);
    X509_free(cert);
    BIO_free_all(bio_in);
    BIO_free_all(bio_out);

    return 0;
}

    int
fc_read_eckey_from_file(const char *fpath, int is_pub_key, EC_KEY **pkey)
{
    FILE *fp = NULL;

    if (is_pub_key)
    {
        if ((fp = fopen(fpath, "rb")) == NULL)
        {
            perror("fopen()");
            return -1;
        }

        *pkey = PEM_read_EC_PUBKEY(fp, NULL, NULL, NULL);
    } else {
        if ((fp = fopen(fpath, "rb")) == NULL)
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
fc_ecdsa_sign(EC_KEY *prikey, const char *const msg, int msglen,
        unsigned char **sigbuff, unsigned int *siglen)
{
    unsigned char digest[EVP_MAX_MD_SIZE] = {0};
    unsigned int digestlen = 0;
    unsigned int keylen = 0;
    int ret = 0;

    fc_sha256_encode(msg, msglen, digest, &digestlen);
    keylen = ECDSA_size(prikey);
    *sigbuff = OPENSSL_malloc(keylen);
    ret = ECDSA_sign(0, digest, digestlen, *sigbuff, siglen, prikey);
    if (ret ==0)
    {}

    return 0;
}

    int
fc_ecdsa_verify(EC_KEY *pubkey, const char *const msg, int msglen,
        const unsigned char *sigbuff, unsigned int siglen)
{
    unsigned char digest[EVP_MAX_MD_SIZE] = {0};
    unsigned int digestlen = 0;
    int ret = 0;

    fc_sha256_encode(msg, msglen, digest, &digestlen);
    ret = ECDSA_verify(0, digest, digestlen, sigbuff, siglen, pubkey);

    return ret;
}

    int
fc_init_crypto_env(FC_server_t *fcserver)
{
    const char *public_key_fname = "/etc/frr/assets/eccpri256.pem";
    const char *private_key_fname = "/etc/frr/assets/eccpri256.key";
    fc_read_eckey_from_file(public_key_fname, 1, &fcserver->pubkey);
    fc_read_eckey_from_file(private_key_fname, 0, &fcserver->prikey);

    return 0;
}

/* FC SERVER UTILS */
    void
fc_server_destroy(int signum)
{
    if (signum == SIGINT)
    {
        printf("recevied SIGINT\n");
        diag_fini();
        if (g_fc_server.fc_bgpd_ctx)
        {
            ncs_manager_stop(g_fc_server.fc_bgpd_ctx);
            ncs_destroy(g_fc_server.fc_bgpd_ctx);
            g_fc_server.fc_bgpd_ctx = NULL;
        }
        fc_db_close(g_fc_server.db);
        fc_hashtable_destroy(&g_fc_server.ht_as);
        // fc_hashtable_destroy(&g_fc_server.ht_prefix);
        EC_KEY_free(g_fc_server.pubkey);
        EC_KEY_free(g_fc_server.prikey);
        printf("bye bye!\n");
        exit(EXIT_SUCCESS);
    }
}

    int
fc_server_create(void)
{
    FC_node_as_t meta;
    FC_ht_node_as_t *node;

    fc_init_db(&g_fc_server.db);

    meta.asn = g_fc_server.local_asn;
    node = htbl_meta_find(&g_fc_server.ht_as, &meta);

    if (node)
    {
        // FC_acs_t *acs = &node->acs;

        if ((g_fc_server.fc_bgpd_ctx = ncs_create(g_fc_server.prog_name, TCP_PROTO))
                == NULL)
        {
            printf("create bgpd ncs failed\n");
            exit(-ENOMEM);
        }

        // ncs_setup(g_fc_server.fc_bgpd_ctx, acs->ipv4, FC_PORT, NULL, 0);
        ncs_setup(g_fc_server.fc_bgpd_ctx, g_fc_server.prog_addr, FC_PORT, NULL, 0);
        ncs_timeout(g_fc_server.fc_bgpd_ctx, 10, -1);
        ncs_setkeepalive(g_fc_server.fc_bgpd_ctx, 10);
        ncs_server_enable(g_fc_server.fc_bgpd_ctx);
        ncs_server_register(g_fc_server.fc_bgpd_ctx, fc_server_handler);
        ncs_manager_start(g_fc_server.fc_bgpd_ctx);
    }

    printf("fc_server : AS %d is ready!!!\n", g_fc_server.local_asn);

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

    static inline int
fc_asn_is_offpath(u32 asn, const FC_msg_bm_t *bm)
{
    int i = 0;

    for (i=0; i<bm->fc_num; ++i)
    {
        if (asn == bm->fclist[i].previous_asn
            || asn == bm->fclist[i].current_asn
            || asn == bm->fclist[i].nexthop_asn)
        {
            return 0;
        }
    }

    return 1;
}

    static int
fc_bm_find_server(uint32_t asn, char *ifaddr, char *ifname)
{
    FC_node_as_t meta;
    FC_ht_node_as_t *node;

    meta.asn = asn;
    node = htbl_meta_find(&g_fc_server.ht_as, &meta);

    if (node)
    {
        memcpy(ifaddr, node->acs.ipv4[0].ifaddr,
                strlen(node->acs.ipv4[0].ifaddr));
        if (ifname)
        {
            memcpy(ifname, node->acs.ipv4[0].ifname,
                    strlen(node->acs.ipv4[0].ifname));
        }
        return 0;
    }

    return -1;
}

    static int
fc_bm_broadcast_to_peer(ncs_ctx_t *ctx, const FC_msg_bm_t *bm, char *buffer,
        int bufferlen)
{
    printf("broadcast to peers start\n");
    int i = 0, ret = 0;
    u32 asn = 0;
    FC_node_as_t meta = {0};
    char ifaddr[INET6_ADDRSTRLEN] = {0};

    for (i=0; i<g_fc_server.asns_num; ++i)
    {
        asn = g_fc_server.asns[i];
        if (g_fc_server.local_asn == asn)
        {
            continue;
        }

        meta.asn = asn;
        FC_ht_node_as_t *node = htbl_meta_find(&g_fc_server.ht_as, &meta);

        if (node)
        {
            // offpath
            if (fc_asn_is_offpath(asn, bm))
            {
                printf("sent to offpath node: %d->remote_addr: %s\n",
                        node->asn, ctx->remote_addr);
                ret = fc_bm_find_server(asn, ifaddr, NULL);
                if (ret == 0)
                {
                    printf("remote-acs addr: %s\n", ifaddr);
                    fc_bm_sent_to_peer(ifaddr, bm, buffer, bufferlen);
                } else
                {
                    printf("Error: cannot find acs\n");
                }
            }
            // onpath
            else
            {
                printf("sent to onpath node: %d->remote_addr: %s\n",
                        node->asn, ctx->remote_addr);
                ret = fc_bm_find_server(asn, ifaddr, NULL);
                if (ret == 0)
                {
                    printf("remote-acs addr: %s\n", ifaddr);
                    fc_bm_sent_to_peer(ifaddr, bm, buffer, bufferlen);
                } else
                {
                    printf("Error: cannot find acs\n");
                }
            }
        }
    }
    /*
    for (i=0; i<bm->fc_num; ++i)
    {
        // TODO wether asn is in aspath
        meta.asn = bm->fclist[i].current_asn;
        FC_ht_node_as_t *node = htbl_meta_find(&g_fc_server.ht_as,
                &meta);
        if (node)
        {
            if (g_fc_server.local_asn != node->asn)
            {
                printf("sent to %d\n", node->asn);
                fc_bm_sent_to_peer(node->acs.ipv4,
                        bm, buffer, bufferlen);
            }
        }
    }
    */

    printf("broadcast to peers done\n");
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
    char buff_ski[FC_BUFF_SIZE256] = {0};
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
        printf("THIS IS NOT supported: %d!\n", bm->ipversion);
        return 0;
    } else
    {
        printf("THIS IS NOT supported: %d!\n", bm->ipversion);
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
        FC_MEM_CHECK(cur >= FC_BUFF_SIZE);
    }
    printf("src-ip: %s\n", buff_src_ip);

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
        snprintf(buff_dst_ip+cur, FC_BUFF_SIZE,
                "/%d,", bm->dst_ip[i].prefix_length);
        cur += strlen(buff_dst_ip+cur);
        FC_MEM_CHECK(cur >= FC_BUFF_SIZE);
    }
    printf("dst-ip: %s\n", buff_dst_ip);
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
        // printf("i: %d, curlen: %d, fclist: %s\n", i, cur, buff_fclist);
        FC_MEM_CHECK(cur >= FC_BUFF_SIZE);
    }
    // fc_base64_encode(buff, cur, buff_fclist);

    /*
       printf("buff-srcip: %s\n", buff_src_ip);
       printf("buff-dstip: %s\n", buff_dst_ip);
       printf("buff-fclist: %s\n", buff_fclist);
       */

    // ski
    cur = 0;
    for (int j=0; j<20; ++j)
    {
        snprintf(buff_ski+cur, FC_BUFF_SIZE256, "%02X",
                bm->fclist[i].ski[j]);
        cur += 2;
        FC_MEM_CHECK(cur >= FC_BUFF_SIZE256);
    }
    // signature
    cur = 0;
    for (int j = 0; j < bm->siglen; ++j)
    {
        snprintf(buff_signature+cur, FC_BUFF_SIZE, "%02X",
                bm->signature[j]);
        cur += 2;
        FC_MEM_CHECK(cur >= FC_BUFF_SIZE);
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
fc_server_pubkey_handler(ncs_ctx_t *ctx, const char *buff, int len)
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
        ret = fc_ecdsa_verify(g_fc_server.pubkey, msg, msglen,
                bm->fclist[i].sig, bm->fclist[i].siglen);
        switch (ret)
        {
        case 1:
            printf("verify fc %d ok\n", i);
            break;
        case 0:
            printf("verify fc %d failed\n", i);
            break;
        default:
            printf("verify fc %d error\n", i);
            break;
        }
    }
    return 0;
}

    static int
fc_gen_acl(ncs_ctx_t *ctx, FC_msg_bm_t *bm)
{
    int i = 0, j = 0, ret = 0;
    int flag_offpath = 0;
    char ifaddr[INET6_ADDRSTRLEN] = {0}, ifname[FC_MAX_SIZE] = {0};
    char saddr[INET6_ADDRSTRLEN] = {0};
    char daddr[INET6_ADDRSTRLEN] = {0};
    u32 asn = 0;

    asn = bm->fclist[0].current_asn;
    if (strcmp("127.0.0.1", ctx->remote_addr) != 0)
    {
        asn = bm->fclist[0].nexthop_asn;
    }

    ret = fc_bm_find_server(asn, ifaddr, ifname);
    if (ret < 0)
    {
        printf("ERROR: there is no such asn: %u\n", asn);
    }
    printf("-=+=-# ifaddr %s, ifname %s #-=+=-\n", ifaddr, ifname);
    flag_offpath = fc_asn_is_offpath(g_fc_server.local_asn, bm);

    inet_ntop(AF_INET, &(((struct sockaddr_in*)&(bm->dst_ip[0].ip))->sin_addr),
            daddr, (socklen_t)sizeof(daddr));

    for (i=0; i<bm->src_ip_num; ++i)
    {
        // TODO ipv6
        inet_ntop(AF_INET, &(((struct sockaddr_in*)&(bm->src_ip[i].ip))->sin_addr),
            saddr, (socklen_t)sizeof(saddr));
        char cmd[1000] = {0};
        if (flag_offpath) // filter: s->d
        {
            for (j=FC_NFT_FILTER_CHAIN_START; j<FC_NFT_FILTER_CHAIN_END; ++j)
            {
                sprintf(cmd, "nft add rule inet filter %s "
                        "ip saddr %s/%d ip daddr %s/%d drop",
                        g_fc_nft_chains[j],
                        saddr, bm->src_ip[0].prefix_length,
                        daddr, bm->dst_ip[0].prefix_length);
                ret = system(cmd);
                // printf("ret = %d, cmd: %s\n", ret, cmd);
            }
        } else // filter: !a->d
        {
            for (j=0; j<g_fc_server.nics_num; ++j)
            {
                if (strcmp(g_fc_server.nics[j], ifname))
                {
                    // sudo nft add rule inet filter output oif ens36
                    //      ip saddr 192.168.88.131 ip daddr 192.168.88.132 drop
                    if (bm->fclist[0].nexthop_asn == g_fc_server.local_asn)
                    {
                        sprintf(cmd, "nft add rule inet filter %s "
                                "oifname %s ip saddr %s/%d ip daddr %s/%d drop",
                                g_fc_nft_chains[FC_NFT_FILTER_CHAIN_OUTPUT],
                                g_fc_server.nics[j],
                                saddr, bm->src_ip[0].prefix_length,
                                daddr, bm->dst_ip[0].prefix_length);
                    } else
                    {
                        sprintf(cmd, "nft add rule inet filter %s "
                                "iifname %s ip saddr %s/%d ip daddr %s/%d drop",
                                bm->fc_num > 1 ?
                                g_fc_nft_chains[FC_NFT_FILTER_CHAIN_FORWARD]
                                : g_fc_nft_chains[FC_NFT_FILTER_CHAIN_INPUT],
                                g_fc_server.nics[j],
                                saddr, bm->src_ip[0].prefix_length,
                                daddr, bm->dst_ip[0].prefix_length);
                    }
                    ret = system(cmd);
                    // printf("ret = %d, cmd: %s\n", ret, cmd);
                }
            }
        }
    }

    return 0;
}


// buff is starting from bm's ipversion
// msg_type: is broadcast msg
    int
fc_server_bm_handler(ncs_ctx_t *ctx, char *buffer, int bufferlen, int msg_type)
{
    // remove header
    char buff_new_msg[BUFSIZ] = {0};
    memcpy(buff_new_msg, buffer, bufferlen);
    char *buff = buff_new_msg + FC_HDR_GENERAL_LENGTH;

    u32 i = 0;
    FC_msg_bm_t bm = {0};
    int cur = 0;
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
        printf("Not supported now: %d\n", buff[0]);
        return 0;
    } else
    {
        printf("Not supported now: %d\n", buff[0]);
        return -1;
    }

    cur += FC_HDR_BM_FIX_LENGTH;
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
            struct sockaddr_in* addr = (struct sockaddr_in*) &bm.src_ip[i].ip;
            memcpy(&(addr->sin_addr),
                    buff+cur, sizeof(struct in_addr));
        } else
        {
            struct sockaddr_in6* addr = (struct sockaddr_in6*) &bm.src_ip[i].ip;
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
            struct sockaddr_in* addr = (struct sockaddr_in*) &bm.dst_ip[i].ip;
            memcpy(&(addr->sin_addr),
                    buff+cur, sizeof(struct in_addr));
        } else
        {
            struct sockaddr_in6* addr = (struct sockaddr_in6*) &bm.dst_ip[i].ip;
            memcpy(&(addr->sin6_addr),
                    buff+cur, sizeof(struct in6_addr));
        }
        memcpy(&bm.dst_ip[i].prefix_length, buff+cur+ip_len, 1);
        cur += ip_len + 1;
    }

    // fclist
    for (i=0; i<bm.fc_num; ++i)
    {
        memcpy(&bm.fclist[i], buff+cur, FC_HDR_FC_FIX_LENGTH);
        cur += FC_HDR_FC_FIX_LENGTH;
        bm.fclist[i].previous_asn = ntohl(bm.fclist[i].previous_asn);
        bm.fclist[i].current_asn = ntohl(bm.fclist[i].current_asn);
        bm.fclist[i].nexthop_asn = ntohl(bm.fclist[i].nexthop_asn);
        bm.fclist[i].siglen = ntohs(bm.fclist[i].siglen);
        memcpy(bm.fclist[i].sig, buff+cur, bm.fclist[i].siglen);
        cur += bm.fclist[i].siglen;

        printf("3 asn: %d, %d, %d, siglen: %d\n", bm.fclist[i].previous_asn,
                bm.fclist[i].current_asn, bm.fclist[i].nexthop_asn,
                bm.fclist[i].siglen);

        if (bm.fclist[i].nexthop_asn == bm.fclist[i].previous_asn)
        {
            printf("not needed fclist\n");
            return -1;
        }
    }

    ret = fc_bm_verify_fc(&bm);
    FC_ASSERT_RET(ret);

    // TODO need read from g_fc_server.
    // ski -- for signature
    memset(bm.ski, 0, FC_SKI_LENGTH);

    // signature to be signed and verified
    // THIS is in network byte order
    memcpy(msg, buff, cur);

    if (msg_type == FC_MSG_BGPD)
    {
        // add signature for sending to peers
        fc_ecdsa_sign(g_fc_server.prikey, msg, cur,
                &sigbuff, &sigbufflen);
        memcpy(buff+cur+FC_SKI_LENGTH, sigbuff, sigbufflen);
        bm.siglen = sigbufflen;
        sigbufflen = htons(sigbufflen);
        memcpy(&buff[FC_HDR_BM_SIGLEN_POS], &sigbufflen, sizeof(bm.siglen));
        memcpy(bm.signature, sigbuff, bm.siglen);
        OPENSSL_free(sigbuff);
        // broadcast to onpath nodes
        buff_new_msg[1] = FC_MSG_BC;  // type: bc msg
        fc_bm_broadcast_to_peer(ctx, &bm, buff_new_msg,
                FC_HDR_GENERAL_LENGTH+cur+FC_SKI_LENGTH+bm.siglen);
    } else if (msg_type == FC_MSG_BC)
    {
        // verify and remove signature
        // SIGLEN MUST be 0 when verify SIGNATURE
        memset(&msg[FC_HDR_BM_SIGLEN_POS], 0, sizeof(16));
        memcpy(bm.signature, buff+cur+FC_SKI_LENGTH, bm.siglen);
        ret = fc_ecdsa_verify(g_fc_server.pubkey, msg, cur,
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
    fc_gen_acl(ctx, &bm);
    fc_db_write_bm(&bm);

    return 0;
}

    int
fc_server_handler(ncs_ctx_t *ctx)
{
    int bufflen = 0;
    int recvlen = 0;
    char buff[BUFSIZ];

    memset(buff, 0, BUFSIZ);
    recvlen = ncs_server_recv(ctx, buff, BUFSIZ);
    memcpy(&bufflen, &buff[2], sizeof(u16));
    bufflen = ntohs(bufflen);

    printf("Accept from: %s:%d\n", ctx->remote_addr, ctx->remote_port);
    printf("bufflen: %d, recvlen: %d\n", bufflen, recvlen);
    /*
    while (bufflen > recvlen)
    {
        recvlen += ncs_server_recv(ctx, buff+recvlen,
                bufflen-recvlen);
    }
    */

    if (buff[0] == FC_VERSION)
    {
        switch (buff[1])
        {
        case 1: // pubkey
            printf("Not support pubkey\n");
            // TODO length
            fc_server_pubkey_handler(ctx, buff, recvlen);
            return 0;
        case 2: // bm
            // TODO length
            fc_server_bm_handler(ctx, buff, recvlen, FC_MSG_BGPD);
            break;
        case 3: // broadcast msg
            // TODO length
            fc_server_bm_handler(ctx, buff, recvlen, FC_MSG_BC);
            break;
        default:
            printf("Not support %d\n", buff[0]);
            return -1;
        }
    } else {
        printf("recvlen: %d\n", recvlen);
        if (recvlen > 1)
        {
            printf("FC HDR VERSION: %d\n", buff[0]);
        }
    }

    printf("#################################################\n\n");

    ncs_client_stop(ctx);

    return 0;
}

    static inline int
print_line(char ch, char *string)
{

    int i = 0, line_len = 84, ln = 40, rn = 40, string_len = 0;

    string_len = strlen(string);
    ln = (line_len - string_len) / 2;
    rn = line_len - string_len - ln;

    printf("*");
    for (i = 0; i < ln; ++i)
        printf("%c", ch);
    printf("%s", string);
    for (i = 0; i < rn; ++i)
        printf("%c", ch);
    printf("*\n");

    return 0;
}

    static inline void
fc_welcome_banner()
{
    char *openssl_ver = OpenSSL_version(OPENSSL_VERSION);

    print_line('*', "");
    print_line(' ', FC_VERSION_STR);
    print_line(' ', "Home page: <https://gitee.com/basil1728/fcbgp-new>");
    print_line(' ', "A private repository. Not avaliable without permission.");
    print_line(' ', "Need help or report bugs please mailto: guoyangfei@zgclab.edu.cn");
    print_line(' ', "SSL_VERSION: " FC_SSL_VERSION);
    print_line('*', "");
}

    static inline void
fc_help(void)
{
    fc_welcome_banner();
    printf("\n");
    printf("\t-f <asnlist.json>  Specify the location of asnlist.json.\n");
    printf("\t                   OPTIONAL. Default location is /etc/frr/assets/\n");
    printf("\t-h                 Print this message.\n");
    printf("\t-v                 Print FC Server version.\n");
}

    static void
fc_parse_args(int argc, char **argv)
{
    int opt = 0;

    while ((opt = getopt(argc, argv, "f:hv")) > 0)
    {
        switch(opt)
        {
        case 'f':
            memcpy(g_fc_server.asnlist_fname, optarg, strlen(optarg));
            break;
        case 'v':
            fc_welcome_banner();
            exit(EXIT_SUCCESS);
        case 'h':
            fc_help();
            exit(EXIT_SUCCESS);
        default:
            fprintf(stderr, "unknown opt: %d\n", opt);
            fc_help();
            exit(EXIT_FAILURE);
        }
    }

    if (strlen(g_fc_server.asnlist_fname) == 0)
    {
        const char *pfname = "/etc/frr/assets/asnlist.json";
        memcpy(g_fc_server.asnlist_fname, pfname, strlen(pfname));
    }
}

    int
fc_main()
{
    g_fc_server.prog_name = "fcserver";
    g_fc_server.prog_addr = "0.0.0.0";

    fc_welcome_banner();

    diag_init(g_fc_server.prog_name);

    fc_hashtable_create(&g_fc_server.ht_as, &g_fc_htbl_as_ops);

    fc_read_asn_ips();
    htbl_display(&g_fc_server.ht_as);

    fc_init_crypto_env(&g_fc_server);

    fc_server_create();

    signal(SIGINT, fc_server_destroy);

    while (1)
    {
        sleep(1);
    }

    return 0;
}

    int
main(int argc, char **argv)
{
    fc_parse_args(argc, argv);
    fc_main();

    return 0;
}
