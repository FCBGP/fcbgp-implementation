#ifndef __LIBTYPES_H__
#define __LIBTYPES_H__

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <ctype.h>
#include <errno.h>
#include <time.h>

#ifndef offsetof
#define offsetof(ptype,field) ((size_t)&(((ptype *)0)->field))
#endif

/*
 * Takes a pointer to a member variable and computes pointer to the structure
 * that contains it. 'type' is type of the structure, not the member.
 */
#ifndef container_of
#define container_of(ptr, type, member) (ptr ? ((type*) (((char*) ptr) - offsetof(type, member))) : NULL)
#endif

#ifndef UNUSED
#if defined __GNUC__ || defined __llvm__
#define UNUSED __attribute__ ((unused))
#else
#define UNUSED
#endif
#endif

#ifndef likely
#if defined __GNUC__ || defined __llvm__
#define likely(x) __builtin_expect ((x), 1)
#define unlikely(x) __builtin_expect ((x), 0)
#else
#define likely(x) (x)
#define unlikely(x) (x)
#endif
#endif

typedef int8_t var_int8_t;
typedef uint8_t var_uint8_t;
typedef int32_t var_int_t;
typedef int32_t var_int32_t;
typedef uint32_t var_uint_t;
typedef uint32_t var_uint32_t;
typedef uint16_t var_uint16_t;
typedef uint64_t var_uint64_t;
typedef intptr_t var_intptr_t;
typedef time_t var_time_t;
typedef char var_boolean_t;
typedef char *var_string_t;
typedef float var_float_t;
typedef double var_double_t;

typedef struct {
    int year;
    int month;
    int day;
    int hour;
    int minute;
    int second;
} var_datetime_t;

typedef struct {
    char strbuf[1024];
} var_strbuf_t;

typedef struct {
    double real;
    double image;
} var_complex_t;

typedef struct {
    int32_t start;
    int32_t end;
} var_range_t;

typedef struct {
    uint8_t mac[6];
} var_ethaddr_t;

typedef struct {
    uint8_t wwnn[8];
} var_wwnn_t;

typedef struct {
    union {
        uint8_t addr8[4];
        uint32_t addr32;
    } u;
} var_ipaddr4_t;

typedef struct {
    uint32_t prefix;
    var_ipaddr4_t ipaddr4;
} var_cidraddr4_t;

typedef struct {
    union {
        uint8_t addr8[16];
        uint16_t addr16[8];
        uint32_t addr32[4];
    } u;
} var_ipaddr6_t;

typedef struct {
    uint32_t prefix;
    var_ipaddr6_t ipaddr6;
} var_cidraddr6_t;

#define MULTI_VALUE_MAX 128
typedef struct {
    int n;
    int32_t v[MULTI_VALUE_MAX];
} var_multi_int_t;

typedef struct {
    int n;
    uint32_t v[MULTI_VALUE_MAX];
} var_multi_uint_t;

typedef struct {
    int n;
    float v[MULTI_VALUE_MAX];
} var_multi_float_t;

typedef struct {
    int n;
    double v[MULTI_VALUE_MAX];
} var_multi_double_t;

typedef struct {
    int n;
    var_range_t v[MULTI_VALUE_MAX];
} var_multi_range_t;

static inline int var_range_match(var_range_t *range, int32_t val)
{
    if (val >= range->start && val <= range->end)
        return 1;
    return 0;
}

static inline int var_multi_range_match(var_multi_range_t *mrange, int32_t val)
{
    int i;

    for (i=0; i<mrange->n; i++) {
        if (var_range_match(mrange->v + i, val)) {
            return 1;
        }
    }

    return 0;
}

#define IPADDRFMT "%hhu.%hhu.%hhu.%hhu"
#define CIDRADDRFMT "%hhu.%hhu.%hhu.%hhu/%hhu"
#define ETHADDRFMT "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx"

#define ARRAYSIZE(x) (sizeof(x)/sizeof((x)[0]))

#define ALIGN16(x) ((((uint32_t)(x)) + 1) & ~1)
#define ALIGN32(x) ((((uint32_t)(x)) + 3) & ~3)
#define ALIGN64(x) ((((uint32_t)(x)) + 7) & ~7)
#define ALIGN(x) ALIGN32(x)

#define ISPOW2(x) (!((x) & ~(-(x))))
#define ONES(n) ((1 << (n)) - 1)
#define BIT(n) (1 << (n))

/* round up the given number $n$ to the nearest power of 2. */
static inline int ceil2n(int n)
{
    --n;
    n |= ( n >> 1 );
    n |= ( n >> 2 );
    n |= ( n >> 4 );
    n |= ( n >> 8 );
    n |= ( n >> 16);
    ++n;

    return n;
}

#define ABS(x) (((x) >= 0) ? (x) : (-(x)))

#define SWAP(a,b) do{ typeof(a) c; c = a; a = b; b = c;}while(0)
#define SWAPINT(a,b) do{ (a) ^= (b); (b) ^= (a); (a) ^= (b);}while(0)

/* compute the minimum of two values. */
#ifndef MIN
#define MIN(x, y) (((x) < (y)) ? (x) : (y))
#endif

#ifndef MIN3
#define MIN3(x, y, z) MIN(x,MIN(y,z))
#endif

#ifndef MIN4
#define MIN4(x,y,z,u) MIN(x,MIN3(y,z,u))
#endif

#ifndef MIN5
#define MIN5(x,y,z,u,v) MIN(x,MIN4(y,z,u,v))
#endif

#ifndef MIN6
#define MIN6(x,y,z,u,v,w) MIN(x,MIN5(y,z,u,v,w))
#endif

/* compute the maximum of two values. */
#ifndef MAX
#define MAX(x, y) (((x) > (y)) ? (x) : (y))
#endif

#ifndef MAX3
#define MAX3(x, y, z) MAX(MAX(x, y), z)
#endif

#ifndef MAX4
#define MAX4(x,y,z,u) MAX(x,MAX3(y,z,u))
#endif

#ifndef MAX5
#define MAX5(x,y,z,u,v) MAX(x,MAX4(y,z,u,v))
#endif

#ifndef MAX6
#define MAX6(x,y,z,u,v,w) MAX(x,MAX5(y,z,u,v,w))
#endif

#define MINMAX(x,lo,hi) ((x)<(lo) ? (lo) : ((x)>(hi) ? (hi) : (x)))
#define CLAMP(x,lo,hi) MINMAX(x,lo,hi)
#define CLAMP8(x) CLAMP(x,0,255)
#define CLAMP16(x) CLAMP(x,0,65535)
#define CLAMP255(x) (((x) & (~0xFF)) ? CLAMP(x,0,255) : (x))
#define MID(x,y,z) MAX((x),MIN((y),(z)))

/* compute the remainder from division (where division is defined such that the
 * remainder is always nonnegative).
 *
 * according to K & R, the value of i % j is undefined for negative operand. It is
 * often the case, however, that we want the result to be cyclical, sothat -1 mod 5 = 4,
 * for example.
 *
 * (notice that we ignore the mathematical possibility of j <= 0, since in such a
 * case there's probably something wrong with the code.)
 */
#define MOD(x, y) (((x) < 0) ? (((-x) % (y)) ? ((y) - ((-(x)) % (y))) : (0)) : ((x) % (y)))
#define RATIO(x,y) (((double) (x)) / ((double) (y)))

#endif
