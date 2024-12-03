#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libendian.h"

/*
 * Return the sum of all the 16-bit subwords in a long.
 * This sums two subwords on a 32-bit machine, and four on 64 bits.
 * The implementation does two vector adds to capture any overflow.
 */
#ifdef __tilegx__
static inline uint32_t csum_long(unsigned long x)
{
    unsigned long ret;
    ret = __insn_v2sadu(x, 0);
    ret = __insn_v2sadu(ret, 0);
    return ret;
}
#else
static inline uint32_t csum_long(unsigned long x)
{
    /* add up 16-bit and 16-bit for 16+c bit */
    x = (x & 0xffff) + (x >> 16);
    /* add up carry.. */
    x = (x & 0xffff) + (x >> 16);
    return x;
}
#endif

/*
 * Fold a partial checksum
 */
uint16_t csum_fold(uint32_t csum)
{
    uint32_t sum = (uint32_t)csum;
    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t)~sum;
}

#ifdef __tilegx__
uint32_t do_csum(const uint8_t* buff, int len)
{
    int odd, count;
    unsigned long result = 0;

    if (len <= 0)
        goto out;
    odd = 1 & (unsigned long)buff;
    if (odd)
    {
#if defined(ARCH_IS_LITTLE_ENDIAN)
        result += (*buff << 8);
#else
        result = *buff;
#endif
        len--;
        buff++;
    }
    count = len >> 1; /* nr of 16-bit words.. */
    if (count)
    {
        if (2 & (unsigned long)buff)
        {
            result += *(const uint16_t*)buff;
            count--;
            len -= 2;
            buff += 2;
        }
        count >>= 1; /* nr of 32-bit words.. */
        if (count)
        {
            if (4 & (unsigned long)buff)
            {
                uint32_t w = *(const uint32_t*)buff;
                result = __insn_v2sadau(result, w, 0);
                count--;
                len -= 4;
                buff += 4;
            }
            count >>= 1; /* nr of 64-bit words.. */

            /*
             * This algorithm could wrap around for very
             * large buffers, but those should be impossible.
             */
            if (count >= 65530)
                goto out;

            while (count)
            {
                unsigned long w = *(const unsigned long*)buff;
                count--;
                buff += sizeof(w);
                result = __insn_v2sadau(result, w, 0);
            }

            if (len & 4)
            {
                uint32_t w = *(const uint32_t*)buff;
                result = __insn_v2sadau(result, w, 0);
                buff += 4;
            }
        }
        if (len & 2)
        {
            result += *(const uint16_t*)buff;
            buff += 2;
        }
    }
    if (len & 1)
    {
#if defined(ARCH_IS_LITTLE_ENDIAN)
        result += *buff;
#else
        result += (*buff << 8);
#endif
    }
    result = csum_long(result);
    if (odd)
        result = ((result >> 8) & 0xff) | ((result & 0xff) << 8);

out:
    return result;
}
#else
static uint32_t do_csum(const uint8_t* buff, int len)
{
    int odd;
    unsigned long result = 0;

    if (len <= 0)
        goto out;
    odd = 1 & (unsigned long)buff;
    if (odd)
    {
#if defined(ARCH_IS_LITTLE_ENDIAN)
        result += (*buff << 8);
#else
        result = *buff;
#endif
        len--;
        buff++;
    }
    if (len >= 2)
    {
        if (2 & (unsigned long)buff)
        {
            result += *(uint16_t*)buff;
            len -= 2;
            buff += 2;
        }
        if (len >= 4)
        {
            const uint8_t* end = buff + ((unsigned)len & ~3);
            uint32_t carry = 0;
            do
            {
                uint32_t w = *(uint32_t*)buff;
                buff += 4;
                result += carry;
                result += w;
                carry = (w > result);
            } while (buff < end);
            result += carry;
            result = (result & 0xffff) + (result >> 16);
        }
        if (len & 2)
        {
            result += *(uint16_t*)buff;
            buff += 2;
        }
    }
    if (len & 1)
    {
#if defined(ARCH_IS_LITTLE_ENDIAN)
        result += *buff;
#else
        result += (*buff << 8);
#endif
    }
    result = csum_long(result);
    if (odd)
        result = ((result >> 8) & 0xff) | ((result & 0xff) << 8);
out:
    return result;
}
#endif

/*
 *  This is a version of ip_compute_csum() optimized for IP headers,
 *  which always checksum on 4 octet boundaries.
 */
uint16_t ip_fast_csum(const void* iph, uint32_t ihl)
{
    return (uint16_t)~do_csum(iph, ihl * 4);
}

uint32_t csum_tcpudp_nofold(uint32_t saddr, uint32_t daddr, uint16_t len,
                            uint16_t proto, uint32_t sum)
{
    unsigned long long s = (uint32_t)sum;

    s += (uint32_t)saddr;
    s += (uint32_t)daddr;
#if defined(ARCH_IS_BIG_ENDIAN)
    s += proto + len;
#else
    s += (proto + len) << 8;
#endif
    s += (s >> 32);
    return (uint32_t)s;
}

/*
 * computes the checksum of a memory block at buff, length len,
 * and adds in "sum" (32-bit)
 *
 * returns a 32-bit number suitable for feeding into itself
 * or csum_tcpudp_magic
 *
 * this function must be called with even lengths, except
 * for the last fragment, which may be odd
 *
 * it's best to have buff aligned on a 32-bit boundary
 */
uint32_t csum_partial(const void* buff, int len, uint32_t wsum)
{
    uint32_t sum = (uint32_t)wsum;
    uint32_t result = do_csum(buff, len);

    /* add in old sum, and carry.. */
    result += sum;
    if (sum > result)
        result += 1;

    return (uint32_t)result;
}
