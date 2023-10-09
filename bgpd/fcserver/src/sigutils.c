/********************************************************************************
 * File Name:    sigutils.c
 * Author:       basilguo@163.com
 * Created Time: 2023-09-28 07:50:01
 * Description:
 ********************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/core_names.h>
#include <openssl/x509.h>

#include "libdiag.h"

int base64_encode(const unsigned char *msg, size_t length, char **b64msg)
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

    *b64msg = (*buff).data;

    return 0;
}

static size_t inline calc_decode_len(const char *b64msg)
{
    size_t len = strlen(b64msg);
    size_t padding = 0;

    if (b64msg[len-1] == '=' && b64msg[len-2] == '=')
        padding = 2;
    else if (b64msg[len-1] == '=')
        padding = 1;

    return (len * 3) / 4 - padding;
}

int base64_decode(const char *b64msg, unsigned char **msg, size_t *length)
{
    BIO *bio, *b64;
    int decode_len = calc_decode_len(b64msg);

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

static int sha256_encode(const char *const msg, unsigned char *digest,
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

    printf("Digest_len is : %u, Digest is: ", *digest_len);
    for (i = 0; i < *digest_len; i++)
        printf("%02x", digest[i]);
    printf("\n");

    return 0;

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

int read_eckey_from_file(int is_pub_key, EC_KEY *pkey)
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

        pkey = PEM_read_EC_PUBKEY(fp, NULL, NULL, NULL);
    } else {
        if ((fp = fopen(private_key_fname, "rb")) == NULL)
        {
            perror("fopen()");
            return -1;
        }
        pkey = PEM_read_ECPrivateKey(fp, NULL, NULL, NULL);
    }
    fclose(fp);

    return 0;
}
