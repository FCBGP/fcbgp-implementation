/********************************************************************************
 * File Name:    sigutils.h
 * Author:       basilguo@163.com
 * Created Time: 2023-12-19 08:58:12
 * Description:  SIG
 ********************************************************************************/

#ifndef SIGUTILS_H
#define SIGUTILS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include "defines.h"

extern int fc_init_crypto_env(FC_server_t *fcserver);
extern int fc_get_ecpubkey_and_ski(u32 asn, const char *fpath,
                                   EC_KEY **eckey, u8 *ecski);
extern int fc_read_eckey_from_file(const char *fpath,
                                   int is_pub_key, EC_KEY **pkey);
extern int fc_base64_encode(const unsigned char *msg,
                            size_t length, char *b64msg);
extern int fc_base64_decode(const char *b64msg, unsigned char **msg,
                            size_t *length);
extern int fc_ecdsa_sign(EC_KEY *prikey, const char *const msg, int msglen,
                         unsigned char **sigbuff, unsigned int *siglen);
extern int fc_ecdsa_verify(EC_KEY *pubkey, const char *const msg, int msglen,
                           const unsigned char *sigbuff, unsigned int siglen);

#endif // SIGUTILS_H
