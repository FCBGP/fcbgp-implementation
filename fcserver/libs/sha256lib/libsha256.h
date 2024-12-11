#ifndef _M_ZSHA256_H
#define _M_ZSHA256_H

#include <memory.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
extern "C"
{
#endif

    int zsha256(const uint8_t* src, uint32_t len, uint32_t* hash);

#ifdef __cplusplus
}
#endif
#endif
