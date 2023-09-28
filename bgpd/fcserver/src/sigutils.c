/********************************************************************************
 * File Name:    sigutils.c
 * Author:       basilguo@163.com
 * Created Time: 2023-09-28 07:50:01
 * Description:
 ********************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <openssl/bio.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/core_names.h>
#include <openssl/x509.h>

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
        pkey = PEM_read_ECPrivateKey(fp, NULL, NULL, NULL)
    }
    fclose(fp);

    return 0;
}
