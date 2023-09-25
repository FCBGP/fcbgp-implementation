/********************************************************************************
* File Name:    bgp_util.h
* Author:       basilguo@163.com
* Created Time: 2023-09-21 03:26:08
* Description:
********************************************************************************/

#ifndef BGP_UTIL_H
#define BGP_UTIL_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <bgp_config.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include "lib/zlog.h"
#include "bgp_config.h"

static int sha256(const unsigned char * const msg, unsigned char *digest,
        unsigned int *digest_len)
{
    int i = 0;
    const EVP_MD *md = NULL;
    EVP_MD_CTX *mdctx = NULL;

    if ((md = EVP_get_digestbyname("sha256")) == NULL)
    {
        fprintf(stderr, "Unknown message digest\n");
        exit(EXIT_FAILURE);
    }

    if ((mdctx = EVP_MD_CTX_new()) == NULL)
    {
        fprintf(stderr, "create md ctx failed\n");
        exit(EXIT_FAILURE);
    }

    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, msg, strlen(msg));
    EVP_DigestFinal_ex(mdctx, digest, digest_len);
    EVP_MD_CTX_free(mdctx);

    zlog_debug("Digest len is : %u", *digest);
    char log_msg[BUFSIZ] = {0};
    for (i=0; i<*digest_len; ++i)
    {
        snprintf(log_msg[i*2], BUFSIZ, "%02x", digest[i]);
    }
    zlog_debug("Digest is : %s", log_msg);

    return 0;
}

#endif // BGP_UTIL_H
