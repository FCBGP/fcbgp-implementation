/********************************************************************************
 * File Name:    test_ecdsa.c
 * Author:       basilguo@163.com
 * Created Time: 2023-09-20 01:23:20
 * Description:  我放弃了，找不到使用OpenSSL3.0的ECDSA例子，还是使用deprecated的好了。
 ********************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <openssl/bio.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/core_names.h>
#include <openssl/x509.h>


int sha256(const char * const msg, int msg_len, unsigned char *digest, unsigned int
        *digest_len)
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
     * Fetch the SHA256 algorithm implementation for doing the digest. We're
     * using the "default" library context here (first NULL parameter), and
     * we're not supplying any particular search criteria for our SHA256
     * implementation (second NULL parameter). Any SHA256 implementation will
     * do.
     * In a larger application this fetch would just be done once, and could
     * be used for multiple calls to other operations such as EVP_DigestInit_ex().
     */
    if ((md = EVP_MD_fetch(NULL, "SHA256", NULL)) == NULL)
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
    if (!EVP_DigestUpdate(mdctx, msg, msg_len))
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

int deprecated()
{
    // 1. create an EC_KEY object
    int ret;
    // ECDSA_SIG *sig;
    EC_KEY *eckey;

    const char *msg = "hello world";
    unsigned char digest[EVP_MAX_MD_SIZE] = {0};
    unsigned int digest_len = 0;

    sha256(msg, strlen(msg), digest, &digest_len);


    eckey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (eckey == NULL)
    {
        printf("eckey new error\n");
        exit(EXIT_FAILURE);
    }
    if (EC_KEY_generate_key(eckey) == 0)
    {
        printf("generate eckey error\n");
        exit(EXIT_FAILURE);
    }

    // compute the ECDSA signature of a SHA-256 hash value
    /*
       sig = ECDSA_do_sign(digest, digest_len, eckey);

       int size = ECDSA_size(eckey);
       int i = 0;

       printf("size: %d\n", size);
       printf("sig->r: %s\nsig->s: %s\n",
       BN_bn2hex(ECDSA_SIG_get0_r(sig)),
       BN_bn2hex(ECDSA_SIG_get0_s(sig)));
       printf("Signature: ");
       for (i=0; i<size; i+=4)
       {
       printf("%08x\n", ((const uint32_t*)sig)[i]);
       }
       printf("\n");
       */

    unsigned char *sigbuff;
    unsigned int sig_len = ECDSA_size(eckey);
    sigbuff = OPENSSL_malloc(sig_len);
    ret = ECDSA_sign(0, digest, digest_len, sigbuff, &sig_len, eckey);

    printf("sig len: %u\nsignature: ", sig_len);
    for (int i=0; i<sig_len; ++i)
    {
        printf("%02x", sigbuff[i]);
    }
    printf("\n");

    // verify
    // ret = ECDSA_do_verify(digest, 32, sig, eckey);
    ret = ECDSA_verify(0, digest, digest_len, sigbuff, sig_len, eckey);

    if (ret == 1)
    {
        printf("verify ok\n");
    }
    else if (ret == 0)
    {
        printf("verify failed\n");
    }
    else
    {
        printf("error\n");
    }

    // ECDSA_SIG_free(sig);
    EC_KEY_free(eckey);

    return 0;
}

static EVP_PKEY *gen_eckey()
{
    /*
     * The libctx and propq can be set if required, they are included here
     * to show how they are passed to EVP_PKEY_CTX_new_from_name().
     */
    OSSL_LIB_CTX *libctx = NULL;
    const char *propq = NULL;
    EVP_PKEY *key = NULL;
    OSSL_PARAM params[3];
    EVP_PKEY_CTX *genctx = NULL;
    const char *curvename = "P-256";
    int use_cofactordh = 1;

    genctx = EVP_PKEY_CTX_new_from_name(libctx, "EC", propq);
    if (genctx == NULL) {
        fprintf(stderr, "EVP_PKEY_CTX_new_from_name() failed\n");
        goto cleanup;
    }

    if (EVP_PKEY_keygen_init(genctx) <= 0) {
        fprintf(stderr, "EVP_PKEY_keygen_init() failed\n");
        goto cleanup;
    }

    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME,
            (char *)curvename, 0);
    /*
     * This is an optional parameter.
     * For many curves where the cofactor is 1, setting this has no effect.
     */
    params[1] = OSSL_PARAM_construct_int(OSSL_PKEY_PARAM_USE_COFACTOR_ECDH,
            &use_cofactordh);
    params[2] = OSSL_PARAM_construct_end();
    if (!EVP_PKEY_CTX_set_params(genctx, params)) {
        fprintf(stderr, "EVP_PKEY_CTX_set_params() failed\n");
        goto cleanup;
    }

    fprintf(stdout, "Generating EC key\n\n");
    if (EVP_PKEY_generate(genctx, &key) <= 0) {
        fprintf(stderr, "EVP_PKEY_generate() failed\n");
        goto cleanup;
    }

cleanup:
    EVP_PKEY_CTX_free(genctx);

    return key;
}

/*
 * The following code shows how retrieve key data from the generated
 * EC key. See doc/man7/EVP_PKEY-EC.pod for more information.
 *
 * EVP_PKEY_print_private() could also be used to display the values.
 */
static int get_key_values(EVP_PKEY *pkey)
{
    int result = 0;
    char out_curvename[80];
    unsigned char out_pubkey[80];
    unsigned char out_privkey[80];
    BIGNUM *out_priv = NULL;
    size_t out_pubkey_len, out_privkey_len = 0;

    if (!EVP_PKEY_get_utf8_string_param(pkey, OSSL_PKEY_PARAM_GROUP_NAME,
                out_curvename, sizeof(out_curvename),
                NULL)) {
        fprintf(stderr, "Failed to get curve name\n");
        goto cleanup;
    }

    if (!EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY,
                out_pubkey, sizeof(out_pubkey),
                &out_pubkey_len)) {
        fprintf(stderr, "Failed to get public key\n");
        goto cleanup;
    }

    if (!EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY, &out_priv)) {
        fprintf(stderr, "Failed to get private key\n");
        goto cleanup;
    }

    out_privkey_len = BN_bn2bin(out_priv, out_privkey);
    if (out_privkey_len <= 0 || out_privkey_len > sizeof(out_privkey)) {
        fprintf(stderr, "BN_bn2bin failed\n");
        goto cleanup;
    }

    fprintf(stdout, "Curve name: %s\n", out_curvename);
    fprintf(stdout, "Public key:\n");
    BIO_dump_indent_fp(stdout, out_pubkey, out_pubkey_len, 2);
    fprintf(stdout, "Private Key:\n");
    BIO_dump_indent_fp(stdout, out_privkey, out_privkey_len, 2);

    result = 1;
cleanup:
    /* Zeroize the private key data when we free it */
    BN_clear_free(out_priv);
    return result;
}

int do_sign(EVP_PKEY *pkey, char *msg, int length)
{
    int ret = 0;
    unsigned char digest[EVP_MAX_MD_SIZE] = {0};
    unsigned int digest_len = 0;
    EVP_PKEY_CTX *sign_ctx = NULL;
    sha256(msg, length, digest, &digest_len);

    unsigned char *sig = NULL;
    EVP_MD_CTX *md_ctx = NULL;

    if((sign_ctx = EVP_PKEY_CTX_new(pkey, NULL)) == NULL)
    {
        fprintf(stderr, "EVP_PKEY_CTX_new failed\n");
        ret = 1;
        goto cleanup;
    }



cleanup:
    EVP_PKEY_CTX_free(sign_ctx);
    if (ret)
        ERR_print_errors_fp(stderr);


    return ret;
}

int openssl3(char *msg, int msg_len)
{
    int ret = -1;
    EVP_PKEY *pkey = NULL;

    if ((pkey = gen_eckey()) == NULL)
    {
        goto cleanup;
    }

     if (!get_key_values(pkey))
         goto cleanup;

     /*
      * At this point we can write out the generated key using
      * i2d_PrivateKey() and i2d_PublicKey() if required.
      */
     ret = 0;

     do_sign(pkey, msg, msg_len);

cleanup:
     if (ret != 0)
         ERR_print_errors_fp(stderr);
     EVP_PKEY_free(pkey);

    return ret;
}

int main(int argc, char *argv[])
{
    openssl3("123", 3);
    printf("+++++++++++++++++++++++++++++\n");
    deprecated();

    return 0;
}

