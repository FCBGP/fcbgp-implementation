#ifndef _LIBMD5_H_
#define _LIBMD5_H_ 1

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h> /* for memcpy() */

typedef struct md5ctx_st
{
    uint32_t buf[4];
    uint32_t bits[2];
    uint8_t in[64];
} md5ctx_t;

extern void md5_init(md5ctx_t* ctx);
extern void md5_update(md5ctx_t* ctx, uint8_t const* buf, unsigned len);
extern void md5_final(md5ctx_t* ctx, uint8_t digest[16]);

extern int strmd5digest(char* str, uint8_t digest[16]);
extern char* strmd5sum(char* str, char* buf, int len);

#endif
