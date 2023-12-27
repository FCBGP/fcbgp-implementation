/********************************************************************************
 * File Name:    sigutils.c
 * Author:       basilguo@163.com
 * Created Time: 2023-12-19 08:59:59
 * Description:
SIGN/VERIFY UTILS
 ********************************************************************************/

#include "sigutils.h"

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
fc_get_ecpubkey_and_ski(u32 asn, const char *fpath,
        EC_KEY **ecpubkey, u8 *ecski)
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
