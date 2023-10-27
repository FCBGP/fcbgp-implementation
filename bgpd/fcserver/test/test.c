/********************************************************************************
* File Name:    test.c
* Author:       basilguo@163.com
* Created Time: 2023-10-20 09:59:11
* Description:  https://wiki.openssl.org/images/archive/d/de/20151009140057%21EngineTester.c
********************************************************************************/

#include <stdio.h>
#include <stdlib.h>

#include <openssl/crypto.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/evp.h>
#include <openssl/err.h>

int main(int argc, char *argv[])
{
    FILE *fp = NULL;
    X509 *cert = NULL;
    EVP_PKEY *pubkey = NULL;
    EC_KEY *eckey_pub = NULL;
    BIO* bio_in = NULL;
    int ret = 0;
    const ASN1_OCTET_STRING *ski = NULL;

    bio_in = BIO_new_file("10.cert", "r");
    if (bio_in == NULL)
    {
        printf("coudlt not  read public key file\n");
        exit(1);
    }

    cert = X509_new();

    if (PEM_read_bio_X509(bio_in, &cert, 0, NULL) == NULL)
    {
        printf("couldn't read certificate from public key file\n");
        exit(1);
    }

    ski = X509_get0_subject_key_id(cert);

    printf("ski %s\n", ski);

    pubkey = X509_get_pubkey(cert);


    eckey_pub = EVP_PKEY_get1_EC_KEY(pubkey);

    (void) ret;

    EC_KEY_free(eckey_pub);
    X509_free(cert);
    BIO_free_all(bio_in);

    return 0;
}
