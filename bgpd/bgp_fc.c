/********************************************************************************
 * File Name:    bgp_fc.c
 * Author:       basilguo@163.com
 * Created Time: 2023-09-25 10:09:53
 * Description:
 ********************************************************************************/

#include <sys/socket.h>
#include <netinet/in.h>
#include <json-c/json.h>

#include "lib/hash.h"
#include "bgpd/bgpd.h"
#include "bgpd/bgp_fc.h"

/* HASHTABLE UTILS */
    static void *
fc_as_node_create(void)
{
    FC_ht_node_as_t *node = malloc(sizeof(FC_ht_node_as_t));
    return node;
}

    static int
fc_as_node_destroy(void *node)
{
    FC_ht_node_as_t *node_as = (FC_ht_node_as_t *)node;
    free(node_as);
    return 0;
}

    static int
fc_as_node_display(void *node)
{
    char ipstr[INET6_ADDRSTRLEN] = {0};
    int i = 0;
    FC_ht_node_as_t *node_as = (FC_ht_node_as_t *) node;

    zlog_debug("asn: %d", node_as->asn);
    zlog_debug("  %s", "acs:");
    zlog_debug("    ipv4: %s", node_as->ap.acs.ipv4);
    zlog_debug("    ipv6: %s", node_as->ap.acs.ipv6);
    zlog_debug("  %s", "prefix:");
    for (i=0; i<node_as->ap.prefix.ip4s_num; ++i)
    {
        inet_ntop(AF_INET, &node_as->ap.prefix.ip4s[i].ip,
                ipstr, (socklen_t)sizeof(ipstr));
        zlog_debug("    ipv4: %s/%d",
                ipstr, node_as->ap.prefix.ip4s[i].prefix_length);
    }
    for (i=0; i<node_as->ap.prefix.ip6s_num; ++i)
    {
        inet_ntop(AF_INET6, &node_as->ap.prefix.ip6s[i].ip,
                ipstr, (socklen_t)sizeof(ipstr));
        zlog_debug("    ipv6: %s/%d",
                ipstr, node_as->ap.prefix.ip6s[i].prefix_length);
    }

    return 0;
}

    static u32
fc_as_hash(u32 asn)
{
    u32 ret = jhash_1word(asn, 0xdeadbeef);
    zlog_debug("ret : %d", ret);
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
    memcpy(&node_as->ap, &meta_as->ap, sizeof(FC_asn_ip_t));

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

    static void *
fc_asprefix_node_create(void)
{
    FC_ht_node_asprefix_t *node = malloc(sizeof(FC_ht_node_asprefix_t));
    memset(node, 0, sizeof(FC_ht_node_asprefix_t));
    return node;
}

    static int
fc_asprefix_node_destroy(void *node)
{
    FC_ht_node_asprefix_t *node_as = (FC_ht_node_asprefix_t *)node;
    free(node_as);
    return 0;
}

    static int
fc_asprefix_node_display(void *node)
{// TODO
    return 0;
}

    static int
fc_asprefix_hash(u32 asn)
{
    int ret = 0;
    ret = jhash_1word(asn, 0xdeadbeef);
    return ret;
}

    static int
fc_asprefix_node_hash(void *node)
{
    FC_ht_node_asprefix_t *node_asprefix = (FC_ht_node_asprefix_t *) node;
    return fc_asprefix_hash(node_asprefix->asn);
}

    static int
fc_asprefix_meta_hash(void *meta)
{
    FC_node_as_t *meta_asprefix = (FC_node_as_t *)meta;
    return fc_asprefix_hash(meta_asprefix->asn);
}

    static int
fc_asprefix_meta_cmp(void *base, void *meta)
{
    FC_ht_node_asprefix_t *node_asprefix = (FC_ht_node_asprefix_t *)base;
    FC_ht_meta_asprefix_t *meta_asprefix = (FC_ht_meta_asprefix_t *)meta;

    return node_asprefix->asn != meta_asprefix->asn;
}

    static int
fc_asprefix_meta_save(void *base, void *meta)
{
    FC_ht_node_asprefix_t *node_asprefix = (FC_ht_node_asprefix_t *)base;
    FC_ht_meta_asprefix_t *meta_asprefix = (FC_ht_meta_asprefix_t *)meta;

    node_asprefix->asn = meta_asprefix->asn;
    memcpy(&node_asprefix->htbl, &meta_asprefix->htbl, sizeof(htbl_ctx_t));

    return 0;
}

htbl_ops_t g_fc_htbl_asprefix_ops = {
    .node_create_func = fc_asprefix_node_create,
    .node_destroy_func = fc_asprefix_node_destroy,
    .node_display_func = fc_asprefix_node_display,
    .node_hash_func = fc_asprefix_node_hash,
    .meta_hash_func = fc_asprefix_meta_hash,
    .meta_cmp_func = fc_asprefix_meta_cmp,
    .meta_save_func = fc_asprefix_meta_save,
};

htbl_ctx_t g_fc_htbl_asprefix = {0};

// 这里需要注意到是，htbl_ops需要是在ht之后不能销毁的
// 所以只能使用g_htbl_ops这种用法了
int fc_hashtable_create(htbl_ctx_t *ht, htbl_ops_t *ops)
{
    int ret = 0;
    ht->bucketcnt = FCSRV_HTBL_BUCKETS_SIZE;
    ht->ops = ops;

    ret = htbl_init(ht);
    FC_ASSERT_RET(ret);

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

/* HASH UTILS */
    static unsigned int
hash_key(const void *data)
{
    int i = 0;
    unsigned int ret = 0xdeadbeef;
    const SKI_ECKEY_t *msg = (const SKI_ECKEY_t*) data;
    const u8 *ski = msg->ski;
    u32 num = msg->asn;

    for (i=0; i<FC_SKI_LENGTH; i+=4)
    {
        num = (ski[i]<<24) + (ski[i+1]<<16) + (ski[i+2]<<8) + ski[i+3];
        ret = jhash_1word(num, ret);
    }

    return ret;
}

    static bool
hash_cmp(const void *a, const void *b)
{
    const SKI_ECKEY_t *msg1 = (const SKI_ECKEY_t*) a;
    const SKI_ECKEY_t *msg2 = (const SKI_ECKEY_t*) b;

    // return !(!! memcmp(msg1->ski, msg2->ski, FC_SKI_LENGTH));
    return msg1->asn == msg2->asn;
}

    int
fc_get_ecpubkey_and_ski(u32 asn, const char *fpath,
        EC_KEY **ecpubkey, u8 *ecski)
{
    X509 *cert = NULL;
    EVP_PKEY *pubkey = NULL;
    BIO *bio_in = NULL;
    BIO *bio_out = NULL;
    const ASN1_OCTET_STRING *ski = NULL;

    if ((bio_in = BIO_new_file(fpath, "r")) == NULL)
    {
        zlog_err("Couldn't read certificate file");
        return -1;
    }

    if ((bio_out = BIO_new_fp(stdout, BIO_NOCLOSE)) == NULL)
    {
        zlog_err("Couldn't create bio_out");
        return -1;
    }

    if ((cert = X509_new()) == NULL)
    {
        zlog_err("X509_new() error");
        return -1;
    }

    if (PEM_read_bio_X509(bio_in, &cert, 0, NULL) == NULL)
    {
        zlog_err("Couldn't read public key from certificate file");
        return -1;
    }

    if ((ski = X509_get0_subject_key_id(cert)) == NULL)
    {
        zlog_err("Couldn't read ski from cert");
        return -1;
    } else
    {
        memcpy(ecski, (u8 *)ski->data, FC_SKI_LENGTH);
        printf("ASN: %u, Subject Key Identifier (SKI): ", asn);
        for (int i = 0; i < ski->length; i++) {
            printf("%02X", ecski[i]);
        }
        printf("\n");
    }

    if ((pubkey = X509_get_pubkey(cert)) == NULL)
    {
        zlog_err("Couldn't read public key from cert");
        return -1;
    } else
    {
        printf("ASN: %u, pubkey: ", asn);
        EVP_PKEY_print_public(bio_out, pubkey, 0, NULL);
    }

    *ecpubkey = EVP_PKEY_get1_EC_KEY(pubkey);

    EVP_PKEY_free(pubkey);
    X509_free(cert);
    BIO_free_all(bio_in);
    BIO_free_all(bio_out);

    return 0;
}

/* JSON UTILS */
    static char *
fc_combine_path(const char *path, const char *filename)
{
    size_t path_len = strlen(path);
    size_t filename_len = strlen(filename);
    size_t combined_len = path_len + filename_len + 2;  // 2 for '/' and '\0'

    char* combined_path = (char*) malloc(combined_len);
    if (combined_path == NULL)
    {
        zlog_err("malloc for combined_path failed");
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
    static int
fc_json_read_config(struct bgp_master *bm)
{
    struct hash *ht = bm->ht_ski_ecpubkey;
    int i, as_num = 0, ret = 0;
    const char *fpath = NULL, *fname = NULL;
    char *fullpath = NULL;
    json_object *root = NULL, *certs_location = NULL;
    json_object *private_key_fname = NULL, *certificate_fname = NULL;
    json_object *as_info_list = NULL, *as_info = NULL;
    json_object *asn = NULL, *cert = NULL;

    root = json_object_from_file(FC_CONFIG_FILE);
    if (root == NULL)
    {
        zlog_err("Couldn't read root json file");
        return -1;
    }

    certs_location = json_object_object_get(root, "certs_location");
    fpath = json_object_get_string(certs_location);

    private_key_fname = json_object_object_get(root, "private_key_fname");
    fname = json_object_get_string(private_key_fname);
    fullpath = fc_combine_path(fpath, fname);
    fc_read_eckey_from_filepath(fullpath, 0, &bm->prikey);
    free(fullpath);

    certificate_fname = json_object_object_get(root, "certificate_fname");
    fname = json_object_get_string(certificate_fname);
    fullpath = fc_combine_path(fpath, fname);
    ret = fc_get_ecpubkey_and_ski(0, fullpath, &bm->pubkey, bm->ski);
    free(fullpath);

    as_info_list = json_object_object_get(root, "as_info_list");
    as_num = json_object_array_length(as_info_list);

    for (i=0; i<as_num; ++i)
    {
        SKI_ECKEY_t data = {0};

        as_info = json_object_array_get_idx(as_info_list, i);
        asn = json_object_object_get(as_info, "asn");
        data.asn = json_object_get_int(asn);

        cert = json_object_object_get(as_info, "cert");
        fullpath = fc_combine_path(fpath, json_object_get_string(cert));

        ret = fc_get_ecpubkey_and_ski(data.asn,
                fullpath, &data.pubkey, data.ski);
        free(fullpath);

        if (ret != 0)
        {
            zlog_err("Couldn't get ecpubkey and ski");
            return ret;
        }

        hash_get(ht, &data, hash_alloc_intern);

        /*
           SKI_ECKEY_t d = {0}, *pd = NULL;
           d.asn = 10;
           pd = hash_lookup(ht, &d);
           if (pd)
           {
           printf("pd_asn: asn: %u, aki: %p\n", pd->asn, pd->ski);
           }
           memset(&d, 0, sizeof(SKI_ECKEY_t));
           memcpy(d.ski, data.ski, FC_SKI_LENGTH);
           pd = hash_lookup(ht, &d);
           if (pd)
           {
           printf("pd_ski: asn: %u, ski: %p\n", pd->asn, pd->ski);
           }
           */
    }

    json_object_put(root);

    return 0;
}

/* SIGN/VERIFY UTILS */
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

    zlog_debug("Digest_len is : %u, Digest is: ", *digest_len);
    /*
       for (int i = 0; i < (int)*digest_len; i++)
       {
       zlog_debug("%02x", digest[i]);
       }
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
fc_read_eckey_from_filepath(const char *file, int is_pub_key, EC_KEY **pkey)
{
    FILE *fp = NULL;

    if (is_pub_key)
    {
        if ((fp = fopen(file, "rb")) == NULL)
        {
            perror("fopen()");
            return -1;
        }

        *pkey = PEM_read_EC_PUBKEY(fp, NULL, NULL, NULL);
    } else {
        if ((fp = fopen(file, "rb")) == NULL)
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
fc_read_eckey_from_file(int is_pub_key, EC_KEY **pkey)
{
    int ret = 0;
    const char *public_key_fname = "/etc/frr/assets/eccpri256.pem";
    const char *private_key_fname = "/etc/frr/assets/eccpri256.key";
    if (is_pub_key)
    {
        ret = fc_read_eckey_from_filepath(public_key_fname, is_pub_key, pkey);
    } else {
        ret = fc_read_eckey_from_filepath(private_key_fname, is_pub_key, pkey);
    }

    return ret;
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
    if (ret == 1)
    {
        zlog_debug("verify ok");
    }
    else if (ret == 0)
    {
        zlog_debug("verify failed");
    } else
    {
        zlog_debug("error");
    }

    return ret;
}

/* FC SERVER UTILS */
/* BGPD TO FCSERVER */
    static int
fc_send_packet_to_fcserver4(char *buff, int bufflen)
{
    int ret = 0;
    int len = 0;
    int sockfd = 0;
    struct sockaddr_in sockaddr;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);

    sockaddr.sin_family = AF_INET;
    sockaddr.sin_port = htons(FC_PORT);
    inet_pton(AF_INET, "127.0.0.1", &sockaddr.sin_addr);

    ret = connect(sockfd, (struct sockaddr *)&sockaddr, sizeof(sockaddr));
    if (ret < 0)
    {
        zlog_debug("connect() error");
        perror("connect()");
        return -1;
    }

    while (len != bufflen)
    {
        len = len + send(sockfd, buff+len, bufflen-len, 0);
        zlog_debug("len = %d, total-length = %d", len, bufflen);
    }

    close(sockfd);

    return 0;
}

    static int
fc_send_packet_to_fcserver6(char *buff, int bufflen)
{
    int ret = 0;
    int len = 0;
    int sockfd = 0;
    struct sockaddr_in6 sockaddr;

    sockfd = socket(AF_INET6, SOCK_STREAM, 0);

    sockaddr.sin6_family = AF_INET6;
    sockaddr.sin6_port = htons(FC_PORT);
    inet_pton(AF_INET6, "::1", &sockaddr.sin6_addr);

    ret = connect(sockfd, (struct sockaddr *)&sockaddr, sizeof(sockaddr));
    if (ret < 0)
    {
        zlog_debug("connect() error");
        perror("connect()");
        return -1;
    }

    while (len != bufflen)
    {
        len = len + send(sockfd, buff+len, bufflen-len, 0);
        zlog_debug("len = %d, total-length = %d", len, bufflen);
    }

    close(sockfd);

    return 0;
}

    int
fc_send_packet_to_fcserver(u8 ipversion, char *buff, int bufflen)
{
    int ret = 0;
    if (ipversion == IPV4)
    {
        ret = fc_send_packet_to_fcserver4(buff, bufflen);
    } else if (ipversion == IPV6)
    {
        ret = fc_send_packet_to_fcserver6(buff, bufflen);
    }

    return ret;
}

    int
bgp_fc_init(struct bgp_master *bm)
{
    int ret = 0;
    bm->ht_ski_ecpubkey = hash_create(hash_key,
            hash_cmp, "SKI --- EC public key");
    ret = fc_json_read_config(bm);

    if (ret != 0)
    {
        zlog_err("failed init bgp fc");
    }

    return 0;
}

    int
bgp_fc_destroy(struct bgp_master *bm)
{
    return 0;
}
