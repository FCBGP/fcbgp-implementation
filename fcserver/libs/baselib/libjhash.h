#ifndef LIBJHASH_H
#define LIBJHASH_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define JHASH_INITVAL 0xdeadbeef

#define JHASH_FINAL(a, b, c)                                                   \
    {                                                                          \
        c ^= b;                                                                \
        c -= jhash_rol32(b, 14);                                               \
        a ^= c;                                                                \
        a -= jhash_rol32(c, 11);                                               \
        b ^= a;                                                                \
        b -= jhash_rol32(a, 25);                                               \
        c ^= b;                                                                \
        c -= jhash_rol32(b, 16);                                               \
        a ^= c;                                                                \
        a -= jhash_rol32(c, 4);                                                \
        b ^= a;                                                                \
        b -= jhash_rol32(a, 14);                                               \
        c ^= b;                                                                \
        c -= jhash_rol32(b, 24);                                               \
    }

static inline uint32_t jhash_rol32(uint32_t word, uint32_t shift)
{
    return (word << shift) | (word >> (32 - shift));
}

static inline uint32_t jhash_3words(uint32_t a, uint32_t b, uint32_t c,
                                    uint32_t initval)
{
    a += JHASH_INITVAL;
    b += JHASH_INITVAL;
    c += initval;

    JHASH_FINAL(a, b, c);

    return c;
}

static inline uint32_t jhash_2words(uint32_t a, uint32_t b, uint32_t initval)
{
    return jhash_3words(a, b, 0, initval);
}

static inline uint32_t jhash_1word(uint32_t a, uint32_t initval)
{
    return jhash_3words(a, 0, 0, initval);
}

#endif
