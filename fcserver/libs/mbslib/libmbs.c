/*
 * MBS: memory buffer string library.
 */
#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libendian.h"
#include "libmbs.h"
#include "libtypes.h"

#ifdef MBS_CACHE_ENABLE
#include "libcache.h"
#endif

enum
{
    MBS_ALLOC_BY_CACHE_32 = 0,
    MBS_ALLOC_BY_CACHE_64,
    MBS_ALLOC_BY_CACHE_128,
    MBS_ALLOC_BY_CACHE_256,
    MBS_ALLOC_BY_CACHE_512,
    MBS_ALLOC_BY_CACHE_1024,
    MBS_ALLOC_BY_CACHE_2048,
    MBS_ALLOC_BY_CACHE_4096,
    MBS_ALLOC_BY_CACHE_8192,
    MBS_ALLOC_BY_CACHE_10240,

    MBS_ALLOC_BY_MALLOC
};

#ifdef MBS_CACHE_ENABLE
static cache_t* g_mbs_cache_32 = NULL;
static cache_t* g_mbs_cache_64 = NULL;
static cache_t* g_mbs_cache_128 = NULL;
static cache_t* g_mbs_cache_256 = NULL;
static cache_t* g_mbs_cache_512 = NULL;
static cache_t* g_mbs_cache_1024 = NULL;
static cache_t* g_mbs_cache_2048 = NULL;
static cache_t* g_mbs_cache_4096 = NULL;
static cache_t* g_mbs_cache_8192 = NULL;
static cache_t* g_mbs_cache_10240 = NULL;
#endif

int mbsinit(int cnt, ...)
{
#ifdef MBS_CACHE_ENABLE
    int i;
    va_list vacnts;
    int cnts[MBS_ALLOC_BY_MALLOC] = {2048, 2048, 1024, 512, 32, 16, 8, 4, 4, 4};

    va_start(vacnts, cnt);
    for (i = 0; i < cnt; i++)
    {
        cnts[i] = va_arg(vacnts, int);
    }
    va_end(vacnts);

    g_mbs_cache_32 = cache_create("mbs32", 0, 32, cnts[0], malloc, free);
    g_mbs_cache_64 = cache_create("mbs64", 0, 64, cnts[1], malloc, free);
    g_mbs_cache_128 = cache_create("mbs128", 0, 128, cnts[2], malloc, free);
    g_mbs_cache_256 = cache_create("mbs256", 0, 256, cnts[3], malloc, free);
    g_mbs_cache_512 = cache_create("mbs512", 0, 512, cnts[4], malloc, free);
    g_mbs_cache_1024 = cache_create("mbs1024", 0, 1024, cnts[5], malloc, free);
    g_mbs_cache_2048 = cache_create("mbs2048", 0, 2048, cnts[6], malloc, free);
    g_mbs_cache_4096 = cache_create("mbs4096", 0, 4096, cnts[7], malloc, free);
    g_mbs_cache_8192 = cache_create("mbs8192", 0, 8192, cnts[8], malloc, free);
    g_mbs_cache_10240 =
        cache_create("mbs10240", 0, 10240, cnts[9], malloc, free);
#endif

    return 0;
}

void mbsfini(void)
{
#ifdef MBS_CACHE_ENABLE
    cache_destroy(&g_mbs_cache_10240);
    cache_destroy(&g_mbs_cache_8192);
    cache_destroy(&g_mbs_cache_4096);
    cache_destroy(&g_mbs_cache_2048);
    cache_destroy(&g_mbs_cache_1024);
    cache_destroy(&g_mbs_cache_512);
    cache_destroy(&g_mbs_cache_256);
    cache_destroy(&g_mbs_cache_128);
    cache_destroy(&g_mbs_cache_64);
    cache_destroy(&g_mbs_cache_32);
#endif
}

mbs_t mbsalloc(int size)
{
    uint8_t type;
    mbs_t mbs = NULL;
    mbs_hdr_t* hdr = NULL;

    int totalsize = MBSHDRSIZE + size + 1;

#ifdef MBS_CACHE_ENABLE
    if (totalsize <= 32)
    {
        hdr = cache_alloc(g_mbs_cache_32);
        if (hdr)
        {
            type = MBS_ALLOC_BY_CACHE_32;
            goto out;
        }
    }

    if (totalsize <= 64)
    {
        hdr = cache_alloc(g_mbs_cache_64);
        if (hdr)
        {
            type = MBS_ALLOC_BY_CACHE_64;
            goto out;
        }
    }

    if (totalsize <= 128)
    {
        hdr = cache_alloc(g_mbs_cache_128);
        if (hdr)
        {
            type = MBS_ALLOC_BY_CACHE_128;
            goto out;
        }
    }

    if (totalsize <= 256)
    {
        hdr = cache_alloc(g_mbs_cache_256);
        if (hdr)
        {
            type = MBS_ALLOC_BY_CACHE_256;
            goto out;
        }
    }

    if (totalsize <= 512)
    {
        hdr = cache_alloc(g_mbs_cache_512);
        if (hdr)
        {
            type = MBS_ALLOC_BY_CACHE_512;
            goto out;
        }
    }

    if (totalsize <= 1024)
    {
        hdr = cache_alloc(g_mbs_cache_1024);
        if (hdr)
        {
            type = MBS_ALLOC_BY_CACHE_1024;
            goto out;
        }
    }

    if (totalsize <= 2048)
    {
        hdr = cache_alloc(g_mbs_cache_2048);
        if (hdr)
        {
            type = MBS_ALLOC_BY_CACHE_2048;
            goto out;
        }
    }

    if (totalsize <= 4096)
    {
        hdr = cache_alloc(g_mbs_cache_4096);
        if (hdr)
        {
            type = MBS_ALLOC_BY_CACHE_4096;
            goto out;
        }
    }

    if (totalsize <= 8192)
    {
        hdr = cache_alloc(g_mbs_cache_8192);
        if (hdr)
        {
            type = MBS_ALLOC_BY_CACHE_8192;
            goto out;
        }
    }

    if (totalsize <= 10240)
    {
        hdr = cache_alloc(g_mbs_cache_10240);
        if (hdr)
        {
            type = MBS_ALLOC_BY_CACHE_10240;
            goto out;
        }
    }
#endif

    hdr = malloc(totalsize);
    if (hdr)
    {
        type = MBS_ALLOC_BY_MALLOC;
        goto out;
    }

    return NULL;

out:
    hdr->len = 0;
    hdr->size = size;
    hdr->type = type;

    mbs = (char*)hdr + MBSHDRSIZE;
    mbs[hdr->len] = '\0';
    return mbs;
}

void mbsfree(mbs_t mbs)
{
    if (mbs)
    {
        mbs_hdr_t* hdr = MBSHDR(mbs);
        switch (hdr->type)
        {
            case MBS_ALLOC_BY_MALLOC:
                free(hdr);
                break;
#ifdef MBS_CACHE_ENABLE
            case MBS_ALLOC_BY_CACHE_32:
                cache_free(g_mbs_cache_32, hdr);
                break;
            case MBS_ALLOC_BY_CACHE_64:
                cache_free(g_mbs_cache_64, hdr);
                break;
            case MBS_ALLOC_BY_CACHE_128:
                cache_free(g_mbs_cache_128, hdr);
                break;
            case MBS_ALLOC_BY_CACHE_256:
                cache_free(g_mbs_cache_256, hdr);
                break;
            case MBS_ALLOC_BY_CACHE_512:
                cache_free(g_mbs_cache_512, hdr);
                break;
            case MBS_ALLOC_BY_CACHE_1024:
                cache_free(g_mbs_cache_1024, hdr);
                break;
            case MBS_ALLOC_BY_CACHE_2048:
                cache_free(g_mbs_cache_2048, hdr);
                break;
            case MBS_ALLOC_BY_CACHE_4096:
                cache_free(g_mbs_cache_4096, hdr);
                break;
            case MBS_ALLOC_BY_CACHE_8192:
                cache_free(g_mbs_cache_8192, hdr);
                break;
            case MBS_ALLOC_BY_CACHE_10240:
                cache_free(g_mbs_cache_10240, hdr);
                break;
#endif
            default:
                break;
        }
    }
}

/*
 * If mbsrealloc() fails the original block is left untouched,
 * it is not freed or moved.
 */
mbs_t mbsrealloc(mbs_t mbs, int size)
{
    int totalsize = 0;
    mbs_hdr_t* ohdr = NULL;
    mbs_hdr_t* nhdr = NULL;
    mbs_t nmbs = NULL;

    if (mbs == NULL)
    {
        return mbsalloc(size);
    }

    if (size == 0)
    {
        mbsfree(mbs);
        return NULL;
    }

    // exceed the max size
    if (size > 0x3FFFFFFF)
    {
        return NULL;
    }

    ohdr = MBSHDR(mbs);
    if (ohdr->size >= size)
    {
        ohdr->size = size;
        mbs[size] = '\0';
        return mbs;
    }

    totalsize = MBSHDRSIZE + size + 1;

    if (ohdr->type == MBS_ALLOC_BY_MALLOC)
    {
        nhdr = realloc(ohdr, totalsize);
        if (nhdr == NULL)
        {
            return NULL;
        }

        nhdr->size = size;
        nmbs = (char*)nhdr + MBSHDRSIZE;
        return nmbs;
    }

#ifdef MBS_CACHE_ENABLE
    if ((totalsize <= 32 && ohdr->type >= MBS_ALLOC_BY_CACHE_32) ||
        (totalsize <= 64 && ohdr->type >= MBS_ALLOC_BY_CACHE_64) ||
        (totalsize <= 128 && ohdr->type >= MBS_ALLOC_BY_CACHE_128) ||
        (totalsize <= 256 && ohdr->type >= MBS_ALLOC_BY_CACHE_256) ||
        (totalsize <= 512 && ohdr->type >= MBS_ALLOC_BY_CACHE_512) ||
        (totalsize <= 1024 && ohdr->type >= MBS_ALLOC_BY_CACHE_1024) ||
        (totalsize <= 2048 && ohdr->type >= MBS_ALLOC_BY_CACHE_2048) ||
        (totalsize <= 4096 && ohdr->type >= MBS_ALLOC_BY_CACHE_4096) ||
        (totalsize <= 8192 && ohdr->type >= MBS_ALLOC_BY_CACHE_8192) ||
        (totalsize <= 10240 && ohdr->type >= MBS_ALLOC_BY_CACHE_10240))
    {
        ohdr->size = size;
        return mbs;
    }

    nmbs = mbsalloc(size);
    if (nmbs == NULL)
    {
        return NULL;
    }

    nhdr = MBSHDR(nmbs);
    nhdr->len = ohdr->len;

    memcpy(nmbs, mbs, ohdr->len);
    nmbs[ohdr->len] = '\0';
    mbsfree(mbs);
    return nmbs;
#else
    return NULL;
#endif
}

mbs_t mbsnewsize(int size) { return mbsalloc(size); }

mbs_t mbsnewlen(char* str, int len)
{
    mbs_t mbs = NULL;

    mbs = mbsalloc(len);
    if (mbs == NULL)
    {
        return NULL;
    }

    if (str && len)
    {
        mbs_hdr_t* hdr = MBSHDR(mbs);

        hdr->len = len;
        memcpy(mbs, str, len);
        mbs[len] = '\0';
    }

    return mbs;
}

mbs_t mbsempty(void) { return mbsnewlen("", 0); }

mbs_t mbsnew(char* str)
{
    if (str)
    {
        return mbsnewlen(str, strlen(str));
    }
    else
    {
        return mbsnewlen("", 0);
    }
}

mbs_t mbsdup(mbs_t mbs) { return mbsnewlen(mbs, mbslen(mbs)); }

int mbssetlen(mbs_t mbs, int len)
{
    mbs_hdr_t* hdr = MBSHDR(mbs);

    if (len > hdr->size)
    {
        return -EOVERFLOW;
    }

    hdr->len = len;
    return 0;
}

int mbsinclen(mbs_t mbs, int inclen)
{
    mbs_hdr_t* hdr = MBSHDR(mbs);

    if (hdr->len + inclen > hdr->size || hdr->len + inclen < 0)
    {
        return -EOVERFLOW;
    }

    hdr->len = hdr->len + inclen;
    mbs[hdr->len] = '\0';
    return 0;
}

int mbscmp(mbs_t s1, mbs_t s2)
{
    if (s1 == NULL || s2 == NULL)
    {
        return -EINVAL;
    }

    return strncmp(s1, s2, mbslen(s1));
}

int mbscasecmp(mbs_t s1, mbs_t s2)
{
    if (s1 == NULL || s2 == NULL)
    {
        return -EINVAL;
    }

    return strncasecmp(s1, s2, mbslen(s1));
}

mbs_t mbsclear(mbs_t mbs)
{
    mbssetlen(mbs, 0);
    mbs[0] = '\0';

    return mbs;
}

mbs_t mbsexpand(mbs_t* pmbs, int inclen)
{
    if (pmbs == NULL)
    {
        return NULL;
    }

    mbs_t mbs = *pmbs;
    if (mbs == NULL)
    {
        mbs = mbsnewsize(inclen);
        *pmbs = mbs;
        return mbs;
    }

    mbs_hdr_t* hdr = MBSHDR(mbs);
    mbs_t nmbs = mbsrealloc(mbs, hdr->size + inclen);
    if (nmbs == NULL)
    {
        return NULL;
    }

    *pmbs = nmbs;
    return nmbs;
}

mbs_t mbsexpandto(mbs_t* pmbs, int destlen)
{
    mbs_t mbs;
    int len = 0;

    if (pmbs == NULL)
    {
        return NULL;
    }

    mbs = *pmbs;
    if (mbs == NULL)
    {
        mbs = mbsnewsize(destlen);
        *pmbs = mbs;
        return mbs;
    }

    len = mbslen(mbs);

    if (destlen <= len)
    {
        return mbs;
    }

    return mbsexpand(pmbs, destlen - len);
}

mbs_t mbscpylen(mbs_t* pmbs, char* s, int len)
{
    mbs_t mbs;
    mbs_t nmbs;
    int size = 0;

    if (pmbs == NULL)
    {
        return NULL;
    }

    mbs = nmbs = *pmbs;
    if (mbs == NULL)
    {
        mbs = mbsnewlen(s, len);
        *pmbs = mbs;
        return mbs;
    }

    size = mbssize(mbs);

    if (size < len)
    {
        nmbs = mbsexpand(pmbs, len - size);
        if (nmbs == NULL)
        {
            return NULL;
        }
    }

    memcpy(nmbs, s, len);
    mbssetlen(nmbs, len);
    nmbs[len] = '\0';
    return nmbs;
}

mbs_t mbscpy(mbs_t* pmbs, char* s) { return mbscpylen(pmbs, s, strlen(s)); }

mbs_t mbscatlen(mbs_t* pmbs, char* s, int len)
{
    mbs_t mbs;
    int curlen;

    if (pmbs == NULL)
    {
        return NULL;
    }

    mbs = *pmbs;
    if (mbs == NULL)
    {
        mbs = mbsnewlen(s, len);
        *pmbs = mbs;
        return mbs;
    }

    curlen = mbslen(mbs);

    if (curlen + len > mbssize(mbs))
    {
        mbs = mbsexpand(pmbs, len);
        if (mbs == NULL)
        {
            return NULL;
        }
    }

    memcpy(mbs + curlen, s, len);
    mbssetlen(mbs, curlen + len);
    mbs[curlen + len] = '\0';
    return mbs;
}

mbs_t mbscat(mbs_t* pmbs, char* s) { return mbscatlen(pmbs, s, strlen(s)); }

mbs_t mbscatmbs(mbs_t* pmbs, mbs_t mbs)
{
    return mbscatlen(pmbs, mbs, mbslen(mbs));
}

mbs_t mbscatchar(mbs_t* pmbs, char c)
{
    char s[2] = {c, '\0'};

    return mbscatlen(pmbs, s, 1);
}

mbs_t mbscatvfmt(mbs_t* pmbs, const char* fmt, va_list ap)
{
    mbs_t nmbs;

    int len = 0;
    char* buf = NULL;

    len = vasprintf(&buf, fmt, ap);
    if (len < 0)
    {
        return NULL;
    }

    nmbs = mbscatlen(pmbs, buf, len);
    free(buf);
    return nmbs;
}

mbs_t mbscatfmt(mbs_t* pmbs, const char* fmt, ...)
{
    mbs_t nmbs;
    va_list ap;

    va_start(ap, fmt);
    nmbs = mbscatvfmt(pmbs, fmt, ap);
    va_end(ap);

    return nmbs;
}

mbs_t mbscatu8(mbs_t* pmbs, uint8_t u8) { return mbscatfmt(pmbs, "%hhx", u8); }

mbs_t mbscatu16(mbs_t* pmbs, uint16_t u16)
{
    return mbscatfmt(pmbs, "%04x", u16);
}

mbs_t mbscatu32(mbs_t* pmbs, uint32_t u32)
{
    return mbscatfmt(pmbs, "%08x", u32);
}

mbs_t mbscatu64(mbs_t* pmbs, uint64_t u64)
{
    return mbscatfmt(pmbs, "%" PRIx64, u64);
}

mbs_t mbscatU8(mbs_t* pmbs, uint8_t U8) { return mbscatfmt(pmbs, "%02X", U8); }

mbs_t mbscatU16(mbs_t* pmbs, uint16_t U16)
{
    return mbscatfmt(pmbs, "%04X", U16);
}

mbs_t mbscatU32(mbs_t* pmbs, uint32_t U32)
{
    return mbscatfmt(pmbs, "%08X", U32);
}

mbs_t mbscatU64(mbs_t* pmbs, uint64_t U64)
{
    return mbscatfmt(pmbs, "%" PRIX64, U64);
}

mbs_t mbscato(mbs_t* pmbs, uint8_t o) { return mbscatlen(pmbs, (char*)&o, 1); }

mbs_t mbscaths(mbs_t* pmbs, uint16_t hs)
{
    return mbscatlen(pmbs, (char*)&hs, 2);
}

mbs_t mbscathl(mbs_t* pmbs, uint32_t hl)
{
    return mbscatlen(pmbs, (char*)&hl, 4);
}

mbs_t mbscathll(mbs_t* pmbs, uint64_t hll)
{
    return mbscatlen(pmbs, (char*)&hll, 8);
}

mbs_t mbscatns(mbs_t* pmbs, uint16_t hs)
{
    uint16_t ns = endian_htons(hs);
    return mbscatlen(pmbs, (char*)&ns, 2);
}

mbs_t mbscatnl(mbs_t* pmbs, uint32_t hl)
{
    uint32_t nl = endian_htonl(hl);
    return mbscatlen(pmbs, (char*)&nl, 4);
}

mbs_t mbscatnll(mbs_t* pmbs, uint64_t hll)
{
    uint64_t nll = endian_htonll(hll);
    return mbscatlen(pmbs, (char*)&nll, 8);
}

mbs_t mbsaddlen(mbs_t* pmbs, char* s, int len)
{
    mbs_t mbs;
    int curlen;

    if (pmbs == NULL)
    {
        return NULL;
    }

    mbs = *pmbs;
    if (mbs == NULL)
    {
        mbs = mbsnewlen(s, len);
        *pmbs = mbs;
        return mbs;
    }

    curlen = mbslen(mbs);

    if (curlen + len + 1 > mbssize(mbs))
    {
        mbs = mbsexpand(pmbs, len + 1);
        if (mbs == NULL)
        {
            return NULL;
        }
    }

    memcpy(mbs + curlen + 1, s, len);
    mbssetlen(mbs, curlen + 1 + len);
    mbs[curlen + 1 + len] = '\0';
    return mbs;
}

mbs_t mbsadd(mbs_t* pmbs, char* s) { return mbsaddlen(pmbs, s, strlen(s)); }

mbs_t mbsaddmbs(mbs_t* pmbs, mbs_t mbs)
{
    return mbsaddlen(pmbs, mbs, mbslen(mbs));
}

mbs_t mbsaddvfmt(mbs_t* pmbs, const char* fmt, va_list ap)
{
    mbs_t nmbs;

    int len = 0;
    char* buf = NULL;

    len = vasprintf(&buf, fmt, ap);
    if (len < 0)
    {
        return NULL;
    }

    nmbs = mbsaddlen(pmbs, buf, len);
    free(buf);
    return nmbs;
}

mbs_t mbsaddfmt(mbs_t* pmbs, const char* fmt, ...)
{
    mbs_t nmbs;
    va_list ap;

    va_start(ap, fmt);
    nmbs = mbsaddvfmt(pmbs, fmt, ap);
    va_end(ap);

    return nmbs;
}

mbs_t mbsjoin(mbs_t* pmbs, int argc, char** argv, char* sep)
{
    int i;
    mbs_t nmbs = NULL;

    for (i = 0; i < argc; i++)
    {
        nmbs = mbscat(pmbs, argv[i]);
        if (i != argc - 1)
        {
            nmbs = mbscat(pmbs, sep);
        }
    }

    return nmbs;
}

mbs_t mbssum(mbs_t* pmbs, int argc, char** argv)
{
    int i;
    mbs_t nmbs = NULL;

    for (i = 0; i < argc; i++)
    {
        nmbs = mbsadd(pmbs, argv[i]);
        if (nmbs == NULL)
        {
            return NULL;
        }
    }

    return nmbs;
}

mbs_t mbstolower(mbs_t mbs)
{
    int i;
    int len = mbslen(mbs);

    for (i = 0; i < len; i++)
    {
        mbs[i] = tolower(mbs[i]);
    }

    return mbs;
}

mbs_t mbstoupper(mbs_t mbs)
{
    int i;
    int len = mbslen(mbs);

    for (i = 0; i < len; i++)
    {
        mbs[i] = toupper(mbs[i]);
    }

    return mbs;
}

mbs_t mbscapitalize(mbs_t mbs)
{
    int i;
    int len = mbslen(mbs);

    mbs[0] = toupper(mbs[0]);
    for (i = 1; i < len; i++)
    {
        mbs[i] = tolower(mbs[i]);
    }

    return mbs;
}

mbs_t mbsrtrim(mbs_t mbs, char* cset)
{
    size_t len;
    char *start, *end, *sp, *ep;
    char* whitespaces = " \t\r\n";

    cset = cset ?: whitespaces;

    sp = start = mbs;
    ep = end = mbs + mbslen(mbs) - 1;

    while (ep > sp && strchr(cset, *ep))
        ep--;
    len = (sp > ep) ? 0 : ((ep - sp) + 1);
    mbs[len] = '\0';
    mbssetlen(mbs, len);
    return mbs;
}

mbs_t mbsltrim(mbs_t mbs, char* cset)
{
    size_t len;
    char *start, *end, *sp, *ep;
    char* whitespaces = " \t\r\n";

    cset = cset ?: whitespaces;

    sp = start = mbs;
    ep = end = mbs + mbslen(mbs) - 1;

    while (sp <= end && strchr(cset, *sp))
        sp++;
    len = (sp > ep) ? 0 : ((ep - sp) + 1);
    if (mbs != sp)
        memmove(mbs, sp, len);
    mbs[len] = '\0';
    mbssetlen(mbs, len);
    return mbs;
}

mbs_t mbstrim(mbs_t mbs, char* cset)
{
    size_t len;
    char *start, *end, *sp, *ep;
    char* whitespaces = " \t\r\n";

    cset = cset ?: whitespaces;

    sp = start = mbs;
    ep = end = mbs + mbslen(mbs) - 1;

    while (sp <= end && strchr(cset, *sp))
        sp++;
    while (ep > sp && strchr(cset, *ep))
        ep--;
    len = (sp > ep) ? 0 : ((ep - sp) + 1);
    if (mbs != sp)
        memmove(mbs, sp, len);
    mbs[len] = '\0';
    mbssetlen(mbs, len);
    return mbs;
}

mbs_t mbsstripwhite(mbs_t mbs) { return mbstrim(mbs, NULL); }

mbs_t mbsrange(mbs_t mbs, int start, int end)
{
    size_t newlen, len = mbslen(mbs);

    if (len == 0)
        return mbs;

    if (start < 0)
    {
        start = len + start;
        if (start < 0)
            start = 0;
    }

    if (end < 0)
    {
        end = len + end;
        if (end < 0)
            end = 0;
    }

    newlen = (start > end) ? 0 : (end - start) + 1;
    if (newlen != 0)
    {
        if (start >= (signed)len)
        {
            newlen = 0;
        }
        else if (end >= (signed)len)
        {
            end = len - 1;
            newlen = (start > end) ? 0 : (end - start) + 1;
        }
    }
    else
    {
        start = 0;
    }

    if (start && newlen)
        memmove(mbs, mbs + start, newlen);
    mbs[newlen] = 0;
    mbssetlen(mbs, newlen);
    return mbs;
}

mbs_t mbssubstring(mbs_t mbs, int start, int end)
{
    size_t newlen, len = mbslen(mbs);

    if (len == 0)
        return mbsempty();

    if (start < 0)
    {
        start = len + start;
        if (start < 0)
            start = 0;
    }

    if (end < 0)
    {
        end = len + end;
        if (end < 0)
            end = 0;
    }

    newlen = (start > end) ? 0 : (end - start) + 1;
    if (newlen != 0)
    {
        if (start >= (signed)len)
        {
            newlen = 0;
        }
        else if (end >= (signed)len)
        {
            end = len - 1;
            newlen = (start > end) ? 0 : (end - start) + 1;
        }
    }
    else
    {
        start = 0;
    }

    if (newlen)
    {
        return mbsnewlen(mbs + start, newlen);
    }
    else
    {
        return mbsempty();
    }
}

mbs_t mbsprecatlen(mbs_t* pmbs, char* s, int len)
{
    mbs_t mbs = NULL;
    mbs_t nmbs = NULL;

    if (pmbs == NULL)
    {
        return NULL;
    }

    mbs = mbsnewlen(s, len);
    if (mbs == NULL)
    {
        return NULL;
    }

    if (*pmbs == NULL)
    {
        *pmbs = mbs;
        return mbs;
    }

    nmbs = mbscatmbs(&mbs, *pmbs);
    if (nmbs == NULL)
    {
        return NULL;
    }

    mbsfree(*pmbs);
    *pmbs = nmbs;
    return nmbs;
}

mbs_t mbsprecat(mbs_t* pmbs, char* s)
{
    return mbsprecatlen(pmbs, s, strlen(s));
}

mbs_t mbsprecatchar(mbs_t* pmbs, char c)
{
    char s[2] = {c, '\0'};

    return mbsprecat(pmbs, s);
}

mbs_t mbsprecatfmt(mbs_t* pmbs, char* fmt, ...)
{
    va_list params;
    mbs_t mbs = NULL;
    mbs_t nmbs = NULL;

    if (pmbs == NULL)
    {
        return NULL;
    }

    va_start(params, fmt);
    mbscatvfmt(&mbs, fmt, params);
    va_end(params);
    if (mbs == NULL)
        return NULL;

    if (*pmbs == NULL)
    {
        *pmbs = mbs;
        return mbs;
    }

    nmbs = mbscatmbs(&mbs, *pmbs);
    if (nmbs == NULL)
    {
        return NULL;
    }

    mbsfree(*pmbs);
    *pmbs = nmbs;
    return nmbs;
}

mbs_t mbsreadline(FILE* fp)
{
    int c;
    int len;
    mbs_t mbs = mbsnewsize(1024);

    while ((c = fgetc(fp)) != EOF)
    {
        mbscatchar(&mbs, (c & 0xFF));
        if (c == '\n')
        {
            break;
        }
    }

    len = mbslen(mbs);
    if (len == 0)
    {
        mbsfree(mbs);
        return NULL; // read EOF
    }

    if (mbs[len - 1] == '\n')
    {
        mbssetlen(mbs, len - 1);
        mbs[len - 1] = '\0';
    }

    len = mbslen(mbs);
    if (len == 0)
    {
        return mbs; // read a empty line
    }

    if (mbs[len - 1] == '\r')
    {
        mbssetlen(mbs, len - 1);
        mbs[len - 1] = '\0';
    }

    return mbs;
}

mbs_t mbscatstdout(mbs_t* pmbs, char* cmd)
{
    int rdlen = 0;
    size_t len = 0;
    FILE* f = NULL;
    char* line = NULL;
    mbs_t nmbs = NULL;

    if (!(f = popen(cmd, "r")))
    {
        return NULL;
    }

    while ((rdlen = getline(&line, &len, f)) != -1)
    {
        nmbs = mbscatlen(pmbs, line, rdlen);
        if (nmbs == NULL)
        {
            free(line);
            pclose(f);
            return NULL;
        }
    }

    free(line);
    pclose(f);
    return nmbs;
}

mbs_t mbscatstdoutvargs(mbs_t* pmbs, char* fmt, ...)
{
    va_list params;
    char* cmd = NULL;
    mbs_t nmbs = NULL;

    va_start(params, fmt);
    vasprintf(&cmd, fmt, params);
    va_end(params);

    nmbs = mbscatstdout(pmbs, cmd);
    if (nmbs == NULL)
    {
        free(cmd);
        return NULL;
    }

    free(cmd);
    return nmbs;
}

mbs_t mbscatmem(mbs_t* pmbs, void* mem, int len)
{
    int i;
    mbs_t nmbs = NULL;
    unsigned char* buf = mem;

    for (i = 0; i < len; i++)
    {
        nmbs = mbscatfmt(pmbs, "%02X", buf[i]);
        if (nmbs == NULL)
        {
            return NULL;
        }
    }

    return nmbs;
}

mbs_t mbsescapejson(mbs_t mbs)
{
    int i;
    mbs_t nmbs = NULL;
    int len = mbslen(mbs);

    nmbs = mbsnewsize(len);
    if (nmbs == NULL)
    {
        return NULL;
    }

    for (i = 0; i < len; i++)
    {
        unsigned char c = mbs[i];
        if (c == '"' || c == '\\' || c == '/')
        {
            mbscatchar(&nmbs, '\\');
            mbscatchar(&nmbs, c);
        }
        else if (c == '\b')
        {
            mbscat(&nmbs, "\\b");
        }
        else if (c == '\f')
        {
            mbscat(&nmbs, "\\f");
        }
        else if (c == '\n')
        {
            mbscat(&nmbs, "\\n");
        }
        else if (c == '\r')
        {
            mbscat(&nmbs, "\\r");
        }
        else if (c == '\t')
        {
            mbscat(&nmbs, "\\t");
        }
        else
        {
            mbscatchar(&nmbs, c);
        }
    }

    return nmbs;
}

mbs_t mbscatescapejson(mbs_t* pmbs, mbs_t mbs)
{
    int i;
    int len = mbslen(mbs);

    if (pmbs == NULL)
    {
        return NULL;
    }

    for (i = 0; i < len; i++)
    {
        unsigned char c = mbs[i];
        if (c == '"' || c == '\\' || c == '/')
        {
            mbscatchar(pmbs, '\\');
            mbscatchar(pmbs, c);
        }
        else if (c == '\b')
        {
            mbscat(pmbs, "\\b");
        }
        else if (c == '\f')
        {
            mbscat(pmbs, "\\f");
        }
        else if (c == '\n')
        {
            mbscat(pmbs, "\\n");
        }
        else if (c == '\r')
        {
            mbscat(pmbs, "\\r");
        }
        else if (c == '\t')
        {
            mbscat(pmbs, "\\t");
        }
        else
        {
            mbscatchar(pmbs, c);
        }
    }

    return *pmbs;
}

mbs_t mbsprint(mbs_t mbs)
{
    int i;
    mbs_t nmbs = NULL;
    int len = mbslen(mbs);

    for (i = 0; i < len + 1; i++)
    {
        if (isprint(mbs[i]))
        {
            mbscatfmt(&nmbs, "%c", mbs[i]);
        }
        else
        {
            mbscatfmt(&nmbs, "\\x%hhx", mbs[i] & 0xFF);
        }
    }

    return nmbs;
}

void mbsdump(mbs_t mbs)
{
    int i;
    mbs_hdr_t* hdr = MBSHDR(mbs);

    printf("mbs size %d len %d type %d data:\n", hdr->size, hdr->len,
           hdr->type);
    for (i = 0; i < hdr->len + 1; i++)
    {
        if (isprint(mbs[i]))
        {
            printf("%c", mbs[i]);
        }
        else
        {
            printf("\\x%hhx", mbs[i] & 0xFF);
        }
    }
    printf("\n");

    return;
}
