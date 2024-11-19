#ifndef LIBENDIAN_H
#define LIBENDIAN_H

#include <stdint.h>
#include <endian.h>
#include <string.h>
#include <byteswap.h>

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define ARCH_IS_LITTLE_ENDIAN
#elif __BYTE_ORDER == __BIG_ENDIAN
#define ARCH_IS_BIG_ENDIAN
#else
#error "UNKNOWN ARCH ENDIAN"
#endif

/*
 * 1 little-endian
 * 0 big-endian
 */
static inline int get_endian(void)
{
    unsigned short i = 1;
    return (int) *((char *) (&i)) ? 1 : 0;
}

/*
 * return a byteswapped 16-bit value
 */
#ifdef __bswap_16
#define endian_swap16(x) __bswap_16(x)
#else
#define endian_swap16(x) ((uint16_t)( \
            (((uint16_t)(x) & (uint16_t)0x00ffU) << 8) | \
            (((uint16_t)(x) & (uint16_t)0xff00U) >> 8)))
#endif

/*
 * return a byteswapped 32-bit value
 */
#ifdef __bswap_32
#define endian_swap32(x) __bswap_32(x)
#else
#define endian_swap32(x) ((uint32_t)( \
            (((uint32_t)(x) & (uint32_t)0x000000ffUL) << 24) | \
            (((uint32_t)(x) & (uint32_t)0x0000ff00UL) <<  8) | \
            (((uint32_t)(x) & (uint32_t)0x00ff0000UL) >>  8) | \
            (((uint32_t)(x) & (uint32_t)0xff000000UL) >> 24)))
#endif

/*
 * return a byteswapped 64-bit value
 */
#ifdef __bswap_64 // how to check it is a function?
#define endian_swap64(x) __bswap_64((uint64_t)x)
#else
#define endian_swap64(x) ((uint64_t)( \
            (((uint64_t)(x) & (uint64_t)0x00000000000000ffULL) << 56) | \
            (((uint64_t)(x) & (uint64_t)0x000000000000ff00ULL) << 40) | \
            (((uint64_t)(x) & (uint64_t)0x0000000000ff0000ULL) << 24) | \
            (((uint64_t)(x) & (uint64_t)0x00000000ff000000ULL) <<  8) | \
            (((uint64_t)(x) & (uint64_t)0x000000ff00000000ULL) >>  8) | \
            (((uint64_t)(x) & (uint64_t)0x0000ff0000000000ULL) >> 24) | \
            (((uint64_t)(x) & (uint64_t)0x00ff000000000000ULL) >> 40) | \
            (((uint64_t)(x) & (uint64_t)0xff00000000000000ULL) >> 56)))
#endif

/*
 * return a word-swapped 32-bit value
 * endian_swahw32(0x12340000) is 0x00001234
 */
#define endian_swahw32(x) ((uint32_t)( \
            (((uint32_t)(x) & (uint32_t)0x0000ffffUL) << 16) | \
            (((uint32_t)(x) & (uint32_t)0xffff0000UL) >> 16)))

/*
 * return a high and low byte-swapped 32-bit value
 * endian_swahb32(0x12345678) is 0x34127856
 */
#define endian_swahb32(x) ((uint32_t)( \
            (((uint32_t)(x) & (uint32_t)0x00ff00ffUL) << 8) | \
            (((uint32_t)(x) & (uint32_t)0xff00ff00UL) >> 8)))

/*
 * return a dword-swapped 64-bit value
 */
#define endian_swahw64(x) ((uint64_t)( \
            (((uint64_t)(x) & (uint64_t)0x00000000ffffffffULL) << 32) | \
            (((uint64_t)(x) & (uint64_t)0xffffffff00000000ULL) >> 32)))

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define endian_le16toh(x) (x)
#define endian_le32toh(x) (x)
#define endian_le64toh(x) (x)
#define endian_htole16(x) (x)
#define endian_htole32(x) (x)
#define endian_htole64(x) (x)
#define endian_ntohs(x) endian_swap16(x)
#define endian_ntohl(x) endian_swap32(x)
#define endian_ntohll(x) endian_swap64(x)
#define endian_htons(x) endian_swap16(x)
#define endian_htonl(x) endian_swap32(x)
#define endian_htonll(x) endian_swap64(x)
#else
#define endian_le16toh(x) endian_swap16(x)
#define endian_le32toh(x) endian_swap32(x)
#define endian_le64toh(x) endian_swap64(x)
#define endian_htole16(x) endian_swap16(x)
#define endian_htole32(x) endian_swap32(x)
#define endian_htole64(x) endian_swap64(x)
#define endian_ntohs(x) (x)
#define endian_ntohl(x) (x)
#define endian_ntohll(x) (x)
#define endian_htons(x) (x)
#define endian_htonl(x) (x)
#define endian_htonll(x) (x)
#endif

static inline uint32_t endian_ntoh24(const uint8_t * p)
{
    return (p[0] << 16) | (p[1] << 8) | p[2];
}

static inline void endian_hton24(uint8_t * p, uint32_t v)
{
    p[0] = (v >> 16) & 0xff;
    p[1] = (v >> 8) & 0xff;
    p[2] = v & 0xff;
}

static inline void endian_memntohl(unsigned char *buf, int len)
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
    int i = 0;
    int max = len / 4;
    uint32_t *ptr = (uint32_t *) buf;
    register uint32_t data;

    for (i = 0; i < max; i++) {
        data = *(ptr + i);
        *(ptr + i) = endian_ntohl(data);
    }
#endif
}

static inline void endian_memhtonl(unsigned char *buf, int len)
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
    int i = 0;
    int max = len / 4;
    uint32_t *ptr = (uint32_t *) buf;
    register uint32_t data;

    for (i = 0; i < max; i++) {
        data = *(ptr + i);
        *(ptr + i) = endian_htonl(data);
    }
#endif
}

static inline void endian_memntohll(unsigned char *buf, int len)
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
    int i = 0;
    int max = len / 8;
    uint64_t *ptr = (uint64_t *) buf;
    register uint64_t data;

    for (i = 0; i < max; i++) {
        data = *(ptr + i);
        *(ptr + i) = endian_ntohll(data);
    }
#endif
}

static inline void endian_memhtonll(unsigned char *buf, int len)
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
    int i = 0;
    int max = len / 8;
    uint64_t *ptr = (uint64_t *) buf;
    register uint64_t data;

    for (i = 0; i < max; i++) {
        data = *(ptr + i);
        *(ptr + i) = endian_htonll(data);
    }
#endif
}

static inline void endian_memcpy_ntohl(unsigned char *dst, unsigned char *src, int len)
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
    int i = 0;
    int max = len / 4;
    uint32_t *pdst = (uint32_t *) dst;
    uint32_t *psrc = (uint32_t *) src;
    register uint32_t data;

    for (i = 0; i < max; i++) {
        data = *(psrc + i);
        *(pdst + i) = endian_ntohl(data);
    }
#else
    memcpy(dst, src, len);
#endif
}

static inline void endian_memcpy_htonl(unsigned char *dst, unsigned char *src, int len)
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
    int i = 0;
    int max = len / 4;
    uint32_t *pdst = (uint32_t *) dst;
    uint32_t *psrc = (uint32_t *) src;
    register uint32_t data;

    for (i = 0; i < max; i++) {
        data = *(psrc + i);
        *(pdst + i) = endian_htonl(data);
    }
#else
    memcpy(dst, src, len);
#endif
}

static inline void endian_memcpy_ntohll(unsigned char *dst, unsigned char *src, int len)
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
    int i = 0;
    int max = len / 8;
    uint64_t *pdst = (uint64_t *) dst;
    uint64_t *psrc = (uint64_t *) src;
    register uint64_t data;

    for (i = 0; i < max; i++) {
        data = *(psrc + i);
        *(pdst + i) = endian_ntohll(data);
    }
#else
    memcpy(dst, src, len);
#endif
}

static inline void endian_memcpy_htonll(unsigned char *dst, unsigned char *src, int len)
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
    int i = 0;
    int max = len / 8;
    uint64_t *pdst = (uint64_t *) dst;
    uint64_t *psrc = (uint64_t *) src;
    register uint64_t data;

    for (i = 0; i < max; i++) {
        data = *(psrc + i);
        *(pdst + i) = endian_htonll(data);
    }
#else
    memcpy(dst, src, len);
#endif
}

static inline void endian_memcpy_swahw64(unsigned char *dst, unsigned char *src, int len)
{
    int i = 0;
    int max = len / 8;
    uint64_t *pdst = (uint64_t *) dst;
    uint64_t *psrc = (uint64_t *) src;
    register uint64_t data;

    for (i = 0; i < max; i++) {
        data = *(psrc + i);
        *(pdst + i) = endian_swahw64(data);
    }
}

#endif
