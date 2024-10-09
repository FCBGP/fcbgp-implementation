/********************************************************************************
 * File Name:    sigutils.c
 * Author:       basilguo@163.com
 * Created Time: 2023-12-19 08:59:59
 * Description:
 SIGN/VERIFY UTILS
 ********************************************************************************/

#include "sigutils.h"
#include "libcrc32.h"
#include "libmd5.h"
#include <errno.h>
#include <string.h>

int fc_base64_encode(const unsigned char *msg, size_t length, char *b64msg)
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
    DIAG_INFO("msg: %s, b64msg: %s, data: %s\n",
              msg, b64msg, (*buff).data);

    return 0;
}

static inline size_t
fc_calc_base64_decode_len(const char *b64msg)
{
    size_t len = strlen(b64msg);
    size_t padding = 0;

    if (b64msg[len - 1] == '=' && b64msg[len - 2] == '=')
        padding = 2;
    else if (b64msg[len - 1] == '=')
        padding = 1;

    return (len * 3) / 4 - padding;
}

int fc_base64_decode(const char *b64msg, unsigned char **msg, size_t *length)
{
    BIO *bio, *b64;
    size_t decode_len = fc_calc_base64_decode_len(b64msg);

    *msg = (unsigned char *)malloc(decode_len + 1);
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
fc_sha_encode(const unsigned char *const msg, int msglen, unsigned char *digest,
              unsigned int *digest_len, const char *sha_hash_algo)
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
    if (!EVP_DigestFinal_ex(mdctx, digest, digest_len))
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
fc_md5_encode(const unsigned char *const msg, int msglen,
              unsigned char *digest, unsigned int *digest_len)
{
    return fc_sha_encode(msg, msglen, digest, digest_len, "MD5");
}

static int
fc_sha1_encode(const unsigned char *const msg, int msglen,
               unsigned char *digest, unsigned int *digest_len)
{
    return fc_sha_encode(msg, msglen, digest, digest_len, "SHA1");
}

static int
fc_sha256_encode(const unsigned char *const msg, int msglen,
                 unsigned char *digest, unsigned int *digest_len)
{
    return fc_sha_encode(msg, msglen, digest, digest_len, "SHA256");
}

static int
fc_get_ski(X509 *cert, u8 *ski, int *skilen)
{
    ASN1_OCTET_STRING *os = NULL;
    X509_EXTENSION *ext = NULL;
    int found = 0;

    int num = X509_get_ext_count(cert);
    for (int i = 0; i < num; i++) {
        // Get extension
        ext = X509_get_ext(cert, i);
        const char *extname =
            OBJ_nid2sn(OBJ_obj2nid(X509_EXTENSION_get_object(ext)));

        // Is Subject Key Identifier ext?
        if (strcasecmp(extname, "subjectKeyIdentifier") == 0) {
            const X509V3_EXT_METHOD *method = X509V3_EXT_get(ext);
            void *ext_data = X509V3_EXT_d2i(ext);

            if (method && ext_data) {
                // Get data
                os = (ASN1_OCTET_STRING *)ext_data;
                *skilen = ASN1_STRING_length(os);
                if (ski) {
                    memcpy(ski, ASN1_STRING_data(os), *skilen);
                    found = 1;
                }
                ASN1_OCTET_STRING_free(os);
                break;
            }
        }
    }

    return found;
}


int fc_get_ecpubkey_and_ski(u32 asn, const char *fpath,
                            EC_KEY **ecpubkey, u8 *ecski)
{
    X509 *cert = NULL;
    EVP_PKEY *pubkey = NULL;
    BIO *bio_in = NULL;
    BIO *bio_out = NULL;

    if ((bio_in = BIO_new_file(fpath, "r")) == NULL)
    {
        DIAG_ERROR("Couldn't read certificate file\n");
        return -1;
    }

    if ((bio_out = BIO_new_fp(stdout, BIO_NOCLOSE)) == NULL)
    {
        DIAG_ERROR("Couldn't create bio_out\n");
        return -1;
    }

    if ((cert = X509_new()) == NULL)
    {
        DIAG_ERROR("X509_new() error\n");
        return -1;
    }

    if (PEM_read_bio_X509(bio_in, &cert, 0, NULL) == NULL)
    {
        DIAG_ERROR("Couldn't read public key from certificate file\n");
        return -1;
    }

    int skilen = 0;
    if (fc_get_ski(cert, ecski, &skilen))
    {
        DIAG_INFO("ASN: %u, ", asn);
        fc_print_bin("ski", ecski, skilen);
    }

    if ((pubkey = X509_get_pubkey(cert)) != NULL)
    {
        DIAG_INFO("ASN: %u, pubkey: ", asn);
        // EVP_PKEY_print_public(bio_out, pubkey, 0, NULL);
    }

    *ecpubkey = EVP_PKEY_get1_EC_KEY(pubkey);

    EVP_PKEY_free(pubkey);
    X509_free(cert);
    BIO_free_all(bio_in);
    BIO_free_all(bio_out);

    return 0;
}

int fc_read_eckey_from_file(const char *fpath, FC_KEY_TYPE key_type, EC_KEY **pkey)
{
    FILE *fp = NULL;

    switch (key_type)
    {
    case FC_KEY_TYPE_PUBLIC:
        if ((fp = fopen(fpath, "rb")) == NULL)
        {
            DIAG_ERROR("fopen(), %s\n", strerror(errno));
            return -1;
        }

        *pkey = PEM_read_EC_PUBKEY(fp, NULL, NULL, NULL);
        break;
    case FC_KEY_TYPE_PRIVATE:
        if ((fp = fopen(fpath, "rb")) == NULL)
        {
            DIAG_ERROR("fopen(), %s\n", strerror(errno));
            return -1;
        }
        *pkey = PEM_read_ECPrivateKey(fp, NULL, NULL, NULL);
        break;
    }
    fclose(fp);

    return 0;
}

static int
fc_hash(const unsigned char *const msg, int msglen,
        unsigned char *digest, unsigned int *digestlen)
{
    uint32_t res = 0;
    // struct timespec sts = {0}, ets = {0};
    // timespec_get(&sts, TIME_UTC);
    switch (g_fc_server.hash_algorithm_id)
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
        res = crc32_run(0, (char *)msg, msglen);
        memcpy(digest, &res, 4);
        *digestlen = 4;
        break;
    default:
        DIAG_ERROR("Unknown Algorithm ID: %d.\n", g_fc_server.hash_algorithm_id);
        return -1;
    }
    // timespec_get(&ets, TIME_UTC);
    // long tvsec = (long)(ets.tv_sec - sts.tv_sec);
    // long tvnsec = (long)(ets.tv_nsec - sts.tv_nsec);
    // if (tvnsec < 0)
    // {
    //     tvnsec = 1 + tvnsec;
    //     tvsec--;
    // }
    // DIAG_INFO("\e[31mHASH FUNC TIME START %ld.%09ld s\e[0m\n", sts.tv_sec, sts.tv_nsec);
    // DIAG_INFO("\e[31mHASH FUNC TIME END   %ld.%09ld s\e[0m\n", ets.tv_sec, ets.tv_nsec);
    // DIAG_INFO("\e[31mTIME SPENT IN HASH   %ld.%09ld s\e[0m\n", tvsec, tvnsec);
    return 0;
}

int fc_ecdsa_sign(EC_KEY *prikey, const unsigned char *const msg, int msglen,
                  unsigned char **sigbuff, unsigned int *siglen)
{
    unsigned char digest[EVP_MAX_MD_SIZE] = {0};
    unsigned int digestlen = 0;
    unsigned int keylen = 0;
    int ret = 0;

    ret = fc_hash(msg, msglen, digest, &digestlen);
    if (ret != 0)
    {
        DIAG_ERROR("Error: cannot find such hash algorithm: %s",
                   g_fc_server.hash_algorithm);
    }

    keylen = ECDSA_size(prikey);
    *sigbuff = OPENSSL_malloc(keylen);
    ret = ECDSA_sign(0, digest, digestlen, *sigbuff, siglen, prikey);

    return ret;
}

int fc_ecdsa_verify(EC_KEY *pubkey, const unsigned char *const msg, int msglen,
                    const unsigned char *sigbuff, unsigned int siglen)
{
    unsigned char digest[EVP_MAX_MD_SIZE] = {0};
    unsigned int digestlen = 0;
    int i = 0, ret = 0;

    ret = fc_hash(msg, msglen, digest, &digestlen);
    if (ret != 0)
    {
        DIAG_ERROR("Error: cannot find such hash algorithm: %s\n",
                   g_fc_server.hash_algorithm);
    }

    DIAG_INFO("\n------------msg-----------------------------msglen: %d\n",
              msglen);

    char tmp[1024];
    int tmplen = sizeof(tmp), tmpcurlen = 0;
    memset(tmp, 0, tmplen);
    for (i = 0; i < msglen; i++)
    {
        snprintf(tmp + tmpcurlen, tmplen, "%02X ", (unsigned char)msg[i]);
        tmpcurlen += 3;
        if ((i + 1) % 16 == 0)
        {
            snprintf(tmp + tmpcurlen, tmplen, "\n");
            tmpcurlen++;
        }
    }
    DIAG_INFO("%s\n", tmp);

    DIAG_INFO("------------sig-----------------------------siglen : % d\n ",
              siglen);
    memset(tmp, 0, tmplen);
    tmpcurlen = 0;
    for (i = 0; i < siglen; i++)
    {
        snprintf(tmp + tmpcurlen, tmplen, "%02X ", (unsigned char)sigbuff[i]);
        tmpcurlen += 3;
        if ((i + 1) % 16 == 0)
        {
            snprintf(tmp + tmpcurlen, tmplen, "\n");
            tmpcurlen++;
        }
    }
    DIAG_INFO("%s\n", tmp);

    DIAG_INFO("-------------hash----------------------------digestlen : % d\n ",
              digestlen);
    memset(tmp, 0, tmplen);
    tmpcurlen = 0;
    for (i = 0; i < digestlen; i++)
    {
        snprintf(tmp + tmpcurlen, tmplen, "%02X ", (unsigned char)digest[i]);
        tmpcurlen += 3;
        if ((i + 1) % 16 == 0)
        {
            snprintf(tmp + tmpcurlen, tmplen, "\n");
            tmpcurlen++;
        }
    }
    DIAG_INFO("%s\n", tmp);
    ret = ECDSA_verify(0, digest, digestlen, sigbuff, siglen, pubkey);

    return ret;
}
