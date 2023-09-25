/********************************************************************************
* File Name:    bgp_util.c
* Author:       basilguo@163.com
* Created Time: 2023-09-25 08:19:54
* Description:
********************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <openssl/bio.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/core_names.h>
#include <openssl/x509.h>

#include "bgp_fc.h"
#include "bgp_util.h"


// reak key from file
int CRYPTO_read_eckey_from_file(const char *fname, EC_KEY **eckey, const int PUB_KEY)
{
    FILE *file = NULL;
    int ret = 0;

    if (!(file = fopen(fname, "rb")))
    {
        ret = -1;
        perror("fopen() error");
        return ret;
    }
    if (PUB_KEY)
    {
        if ((*eckey = PEM_read_EC_PUBKEY(file, NULL, NULL, NULL)) == NULL)
        {
            ret = -2;
            perror("PEM_read_EC_PUBKEY() error");
        }
    } else { // private ECKEY
        if ((*eckey = PEM_read_ECPrivateKey(file, NULL, NULL, NULL)) == NULL)
        {
            ret = -2;
            perror("PEM_read_ECPrivateKey() error");
        }
    }

    fclose(file);

    return ret;
}
// sha256(msg, digest, &digest_len);
// ret = ECDSA_verify(0, digest, digest_len, sigbuff, sig_len, eckey);
// ret = ECDSA_sign(0, digest, digest_len, sigbuff, &sig_len, eckey);
