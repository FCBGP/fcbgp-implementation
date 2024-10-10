/********************************************************************************
 * File Name:    bgp_fc.c
 * Author:       basilguo@163.com
 * Created Time: 2023-09-25 10:09:53
 * Description: Don't Delete the blank line among these #include; otherwise,
 *  compile will encounter errors.
 ********************************************************************************/

#include "bgpd/bgp_fc.h"
#include "bgpd/bgpd.h"
#include "lib/hash.h"
#include <json-c/json.h>
#include <netinet/in.h>
#include <sys/socket.h>

/* UTILS */
void fc_print_bin(const char *msg, void *data, int len)
{
    int i = 0, curlen = 0;
    char pmsg[BUFSIZ] = {0};
    zlog_debug("%s", msg);

    for (i = 0; i < len; ++i)
    {
        snprintf(pmsg + curlen, BUFSIZ,
                 "%02X", *((u8*)data + i));
        curlen += 2;
        if ((i + 1) % 16 == 0)
        {
            snprintf(pmsg + curlen, BUFSIZ, "\n");
        }
        else if ((i + 1) % 2 == 0)
        {
            snprintf(pmsg + curlen, BUFSIZ, " ");
        }
    }
    zlog_debug("%s", pmsg);
}

/* HASHTABLE UTILS */
/* asn-local-info hash utils */
unsigned int fc_ht_as_hash_key(const void *data)
{
    FC_ht_node_as_t *msg = (FC_ht_node_as_t *)data;
    return jhash_1word(msg->asn, 0xdeadbeef);
}

bool fc_ht_as_hash_cmp(const void *a, const void *b)
{
    FC_ht_node_as_t *msg1 = (FC_ht_node_as_t *)a;
    FC_ht_node_as_t *msg2 = (FC_ht_node_as_t *)b;
    return msg1->asn == msg2->asn;
}

/* asn-prefix hash utils */
unsigned int fc_ht_asprefix_hash_key(const void *data)
{
    unsigned int ret = 0xdeadbeef;
    const FC_ht_node_asprefix_t *msg = (const FC_ht_node_asprefix_t *)data;
    ret = jhash_1word(msg->asn, ret);
    return ret;
}

bool fc_ht_asprefix_hash_cmp(const void *a, const void *b)
{
    const FC_ht_node_asprefix_t *msg1 = (const FC_ht_node_asprefix_t *)a;
    const FC_ht_node_asprefix_t *msg2 = (const FC_ht_node_asprefix_t *)b;
    return msg1->asn == msg2->asn;
}

/* prefix-FCList hash utils */
unsigned int fc_ht_prefix_hash_key(const void *data)
{
    const FCList_t *msg = (const FCList_t *)data;
    int i = 0, ret = 0;
    ret = jhash_2words(msg->ipprefix.family,
                       msg->ipprefix.prefixlen,
                       0xdeadbeef);
    for (i = 0; i < 4; ++i)
        ret = jhash_2words(ret, msg->ipprefix.u.val32[i], 0xdeadbeef);
    return ret;
}

bool fc_ht_prefix_hash_cmp(const void *a, const void *b)
{
    FCList_t *prefix1 = (FCList_t *)a;
    FCList_t *prefix2 = (FCList_t *)b;

    if (prefix1->ipprefix.family == prefix2->ipprefix.family)
    {
        if (prefix1->ipprefix.prefixlen == prefix2->ipprefix.prefixlen)
        {
            for (int i = 0; i < 4; ++i)
            {
                if (prefix1->ipprefix.u.val32[i] !=
                    prefix2->ipprefix.u.val32[i])
                {
                    return false;
                }
            }
        }
    }

    return true;
}

/* ski-ecpubkey hash utils*/
unsigned int fc_ht_ski_eckey_hash_key(const void *data)
{
    int i = 0;
    unsigned int ret = 0xdeadbeef;
    const SKI_ECKEY_t *msg = (const SKI_ECKEY_t *)data;
    const u8 *ski = msg->ski;
    u32 num = msg->asn;

    for (i = 0; i < FC_SKI_LENGTH; i += 4)
    {
        num = (ski[i] << 24) + (ski[i + 1] << 16) + (ski[i + 2] << 8) + ski[i + 3];
        ret = jhash_1word(num, ret);
    }

    return ret;
}

bool fc_ht_ski_eckey_hash_cmp(const void *a, const void *b)
{
    const SKI_ECKEY_t *msg1 = (const SKI_ECKEY_t *)a;
    const SKI_ECKEY_t *msg2 = (const SKI_ECKEY_t *)b;

    // return !(!! memcmp(msg1->ski, msg2->ski, FC_SKI_LENGTH));
    return msg1->asn == msg2->asn;
}

int fc_get_ecpubkey_and_ski(u32 asn, const char *fpath,
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
    }
    else
    {
        memcpy(ecski, (u8 *)ski->data, FC_SKI_LENGTH);
        printf("ASN: %u, Subject Key Identifier (SKI): ", asn);
        for (int i = 0; i < ski->length; i++)
        {
            printf("%02X", ecski[i]);
        }
        printf("\n");
    }

    if ((pubkey = X509_get_pubkey(cert)) == NULL)
    {
        zlog_err("Couldn't read public key from cert");
        return -1;
    }
    else
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
    size_t combined_len = path_len + filename_len + 2; // 2 for '/' and '\0'

    char *combined_path = (char *)malloc(combined_len);
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

static int fc_set_hash_algo_id(const char *hash_algorithm,
                               int *hash_algorithm_id)
{
    if (!strcasecmp(hash_algorithm, "sha256"))
    {
        *hash_algorithm_id = FC_HASH_ALGO_SHA256;
    }
    else if (!strcasecmp(hash_algorithm, "sha1"))
    {
        *hash_algorithm_id = FC_HASH_ALGO_SHA1;
    }
    else if (!strcasecmp(hash_algorithm, "crc32"))
    {
        *hash_algorithm_id = FC_HASH_ALGO_CRC32;
    }
    else if (!strcasecmp(hash_algorithm, "md5"))
    {
        *hash_algorithm_id = FC_HASH_ALGO_MD5;
    }
    else
    {
        *hash_algorithm_id = FC_HASH_ALGO_UNKNOWN;
    }

    return 0;
}

static int
fc_json_read_config(struct bgp_master *bm)
{
    struct hash *ht = bm->fc_config.fc_ht_ski_ecpubkey;
    int i, as_num = 0, ret = 0;
    const char *fpath = NULL, *fname = NULL;
    char *fullpath = NULL;
    json_object *root = NULL, *certs_location = NULL, *jlisten_port = NULL;
    json_object *private_key_fname = NULL, *certificate_fname = NULL;
    json_object *as_info_list = NULL, *as_info = NULL;
    json_object *asn = NULL, *cert = NULL, *hash_algorithm = NULL;

    root = json_object_from_file(FC_CONFIG_FILE);
    if (root == NULL)
    {
        zlog_err("Couldn't read root json file");
        return -1;
    }

    jlisten_port = json_object_object_get(root, "listen_port");
    if (jlisten_port)
    {
        bm->fc_config.fc_listen_port = json_object_get_int(jlisten_port);
    }
    else
    {
        bm->fc_config.fc_listen_port = FC_CFG_DEFAULT_LISTEN_PORT;
    }

    hash_algorithm = json_object_object_get(root, "hash_algorithm");
    if (hash_algorithm)
    {

        const char *tmp_str = json_object_get_string(hash_algorithm);
        fc_set_hash_algo_id(tmp_str, &bm->fc_config.hash_algorithm_id);
    }
    else
    {
        fc_set_hash_algo_id(FC_CFG_DEFAULT_HASH_ALGO,
                            &bm->fc_config.hash_algorithm_id);
    }

    certs_location = json_object_object_get(root, "certs_location");
    fpath = json_object_get_string(certs_location);

    private_key_fname = json_object_object_get(root, "private_key_fname");
    fname = json_object_get_string(private_key_fname);
    fullpath = fc_combine_path(fpath, fname);
    fc_read_eckey_from_filepath(fullpath,
                                0,
                                &bm->fc_config.prikey);
    free(fullpath);

    certificate_fname = json_object_object_get(root, "certificate_fname");
    fname = json_object_get_string(certificate_fname);
    fullpath = fc_combine_path(fpath, fname);
    ret = fc_get_ecpubkey_and_ski(0, fullpath,
                                  &bm->fc_config.pubkey,
                                  bm->fc_config.ski);
    free(fullpath);

    as_info_list = json_object_object_get(root, "as_info_list");
    as_num = json_object_array_length(as_info_list);

    for (i = 0; i < as_num; ++i)
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
fc_hash_encode(const char *const msg, int msglen, unsigned char *digest,
               unsigned int *digestlen, const char *sha_hash_algo)
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
     * Fetch the SHA256 or SHA1 algorithm implementation for doing the digest.
     *
     * We're using the "default" library context here (first NULL parameter),
     * and we're not supplying any particular search criteria for our SHA256
     * or SHA1 implementation (second NULL parameter).
     * Any SHA256 implementation will do.
     * In a larger application this fetch would just be done once, and could
     * be used for multiple calls to other operations such as
     * EVP_DigestInit_ex().
     * */
    if ((md = EVP_MD_fetch(NULL, sha_hash_algo, NULL)) == NULL)
    {
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
     *  goto error;
     * }
     **/
    /* Allocate the output buffer */
    if (!EVP_DigestFinal_ex(mdctx, digest, digestlen))
    {
        goto error;
    }

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

static int
fc_crc_encode(const char *const msg, int msglen, unsigned char *digest,
              unsigned int *digestlen)
{
    // uint32_t res = 0;
    // res = crc32_run(0, msg, msglen);
    // memcpy(digest, &res, 4);
    // *digestlen = 4;
    return 0;
}

static int
fc_md5_encode(const char *const msg, int msglen, unsigned char *digest,
              unsigned int *digestlen)
{
    return fc_hash_encode(msg, msglen, digest, digestlen, "MD5");
}

static int
fc_sha1_encode(const char *const msg, int msglen, unsigned char *digest,
               unsigned int *digestlen)
{
    return fc_hash_encode(msg, msglen, digest, digestlen, "SHA1");
}

static int
fc_sha256_encode(const char *const msg, int msglen, unsigned char *digest,
                 unsigned int *digestlen)
{
    return fc_hash_encode(msg, msglen, digest, digestlen, "SHA256");
}

int fc_read_eckey_from_filepath(const char *file, int is_pub_key, EC_KEY **pkey)
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
    }
    else
    {
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

int fc_read_eckey_from_file(int is_pub_key, EC_KEY **pkey)
{
    int ret = 0;
    const char *public_key_fname = "/etc/frr/assets/eccpri256.pem";
    const char *private_key_fname = "/etc/frr/assets/eccpri256.key";
    if (is_pub_key)
    {
        ret = fc_read_eckey_from_filepath(public_key_fname, is_pub_key, pkey);
    }
    else
    {
        ret = fc_read_eckey_from_filepath(private_key_fname, is_pub_key, pkey);
    }

    return ret;
}

static int
fc_hash(const char *const msg, int msglen,
        unsigned char *digest,
        unsigned int *digestlen)
{
    struct timespec sts = {0}, ets = {0};
    timespec_get(&sts, TIME_UTC);
    switch (bm->fc_config.hash_algorithm_id)
    {
    case FC_HASH_ALGO_SHA256:
        fc_sha256_encode(msg, msglen, digest, digestlen);
        break;
    case FC_HASH_ALGO_SHA1:
        fc_sha1_encode(msg, msglen, digest, digestlen);
        break;
    case FC_HASH_ALGO_MD5:
        fc_md5_encode(msg, msglen, digest, digestlen);
        break;
    case FC_HASH_ALGO_CRC32:
        // TODO
        fc_crc_encode(msg, msglen, digest, digestlen);
        break;
    default:
        zlog_err("I don't know what algorithm should I use.");
        return -1;
    }
    timespec_get(&ets, TIME_UTC);
    long tvsec = (long)(ets.tv_sec - sts.tv_sec);
    long tvnsec = (long)(ets.tv_nsec - sts.tv_nsec);
    if (tvnsec < 0)
    {
        tvnsec = 1 + tvnsec;
        tvsec--;
    }
    zlog_debug("HASH FUNC TIME START %ld.%09ld s", sts.tv_sec, sts.tv_nsec);
    zlog_debug("HASH FUNC TIME END   %ld.%09ld s", ets.tv_sec, ets.tv_nsec);
    zlog_debug("TIME SPENT IN HASH   %ld.%09ld s", tvsec, tvnsec);
    return 0;
}

int fc_ecdsa_sign(EC_KEY *prikey, const char *const msg, int msglen,
                  unsigned char **sigbuff, unsigned int *siglen)
{
    unsigned char digest[EVP_MAX_MD_SIZE] = {0};
    unsigned int digestlen = 0;
    unsigned int keylen = 0;
    int ret = 0;

    ret = fc_hash(msg, msglen, digest, &digestlen);
    if (ret != 0)
    {
        zlog_err("Cannot find such hash algorithm");
    }

    zlog_debug("-----------digest----------------------------");
    unsigned int haha = 0;
    for (haha = 0; haha < digestlen; haha++)
    {
        zlog_debug("%02X ", digest[haha]);
    }

    keylen = ECDSA_size(prikey);
    *sigbuff = OPENSSL_malloc(keylen);
    ret = ECDSA_sign(0, digest, digestlen, *sigbuff, siglen, prikey);
    if (ret == 0) // error
    {
    }

    return 0;
}

int fc_ecdsa_verify(EC_KEY *pubkey, const char *const msg, int msglen,
                    const unsigned char *sigbuff, unsigned int siglen)
{
    unsigned char digest[EVP_MAX_MD_SIZE] = {0};
    unsigned int digestlen = 0;
    int ret = 0;

    ret = fc_hash(msg, msglen, digest, &digestlen);
    if (ret != 0)
    {
        zlog_err("Cannot find such hash algorithm");
    }
    ret = ECDSA_verify(0, digest, digestlen, sigbuff, siglen, pubkey);
    if (ret == -1) // error
    {
    }
    else if (ret == 0) // invalid signature
    {
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
    sockaddr.sin_port = htons(bm->fc_config.fc_listen_port);
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
        len = len + send(sockfd, buff + len, bufflen - len, 0);
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
    sockaddr.sin6_port = htons(bm->fc_config.fc_listen_port);
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
        len = len + send(sockfd, buff + len, bufflen - len, 0);
        zlog_debug("len = %d, total-length = %d", len, bufflen);
    }

    close(sockfd);

    return 0;
}

int fc_send_packet_to_fcserver(u8 ipversion, char *buff, int bufflen)
{
    int ret = 0;
    if (ipversion == IPV4)
    {
        ret = fc_send_packet_to_fcserver4(buff, bufflen);
    }
    else if (ipversion == IPV6)
    {
        ret = fc_send_packet_to_fcserver6(buff, bufflen);
    }

    return ret;
}

int bgp_fc_init(struct bgp_master *bm)
{
    int ret = 0;

    bm->fc_config.fc_ht_asprefix = hash_create(fc_ht_asprefix_hash_key,
                                               fc_ht_asprefix_hash_cmp,
                                               "FC AS Prefix Hashtable");
    bm->fc_config.fc_ht_ski_ecpubkey = hash_create(fc_ht_ski_eckey_hash_key,
                                                   fc_ht_ski_eckey_hash_cmp,
                                                   "SKI --- EC public key");
    ret = fc_json_read_config(bm);

    if (ret != 0)
    {
        zlog_err("failed init bgp fc");
    }

    return 0;
}

int bgp_fc_destroy(struct bgp_master *bm)
{
    return 0;
}
