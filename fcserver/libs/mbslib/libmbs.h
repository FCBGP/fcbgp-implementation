#ifndef __MBS_H__
#define __MBS_H__

/*
 * MBS: memory buffer string library.
 */

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct
{
    uint64_t type : 4;
    uint64_t len : 30;
    uint64_t size : 30;
} mbs_hdr_t;

typedef char* mbs_t;

#define MBSHDRSIZE sizeof(mbs_hdr_t)
#define MBSHDR(mbs) ((mbs_hdr_t*)((mbs)-MBSHDRSIZE))

static inline int mbslen(mbs_t mbs)
{
    if (mbs == NULL)
    {
        return 0;
    }

    return MBSHDR(mbs)->len;
}

static inline int mbssize(mbs_t mbs)
{
    if (mbs == NULL)
    {
        return 0;
    }

    return MBSHDR(mbs)->size;
}

static inline int mbsavail(mbs_t mbs)
{
    if (mbs == NULL)
    {
        return 0;
    }

    return MBSHDR(mbs)->size - MBSHDR(mbs)->len;
}

static inline int mbsisempty(mbs_t mbs)
{
    if (mbs == NULL || MBSHDR(mbs)->len == 0)
    {
        return 1;
    }

    return 0;
}

extern int mbsinit(int cnt, ...);
extern void mbsfini(void);
extern mbs_t mbsalloc(int size);
extern void mbsfree(mbs_t mbs);
extern mbs_t mbsrealloc(mbs_t mbs, int size);
extern mbs_t mbsnewsize(int size);
extern mbs_t mbsnewlen(char* str, int len);
extern mbs_t mbsempty(void);
extern mbs_t mbsnew(char* str);
extern mbs_t mbsdup(mbs_t mbs);
extern int mbssetlen(mbs_t mbs, int len);
extern int mbsinclen(mbs_t mbs, int inclen);
extern int mbscmp(mbs_t s1, mbs_t s2);
extern int mbscasecmp(mbs_t s1, mbs_t s2);
extern mbs_t mbsclear(mbs_t mbs);
extern mbs_t mbsexpand(mbs_t* pmbs, int inclen);
extern mbs_t mbsexpandto(mbs_t* pmbs, int destlen);
extern mbs_t mbscpylen(mbs_t* pmbs, char* s, int len);
extern mbs_t mbscpy(mbs_t* pmbs, char* s);
extern mbs_t mbscatlen(mbs_t* pmbs, char* s, int len);
extern mbs_t mbscat(mbs_t* pmbs, char* s);
extern mbs_t mbscatmbs(mbs_t* pmbs, mbs_t mbs);
extern mbs_t mbscatchar(mbs_t* pmbs, char c);
extern mbs_t mbscatvfmt(mbs_t* pmbs, const char* fmt, va_list ap);
extern mbs_t mbscatfmt(mbs_t* pmbs, const char* fmt, ...);
extern mbs_t mbscatu8(mbs_t* pmbs,
                      uint8_t u8); // catenate a u8 in format "%hhx"
extern mbs_t mbscatu16(mbs_t* pmbs,
                       uint16_t u16); // catenate a u16 in format "%04x"
extern mbs_t mbscatu32(mbs_t* pmbs,
                       uint32_t u32); // catenate a u32 in format "%08x"
extern mbs_t mbscatu64(mbs_t* pmbs,
                       uint64_t u64); // catenate a u64 in format "%"PRIx64
extern mbs_t mbscatU8(mbs_t* pmbs,
                      uint8_t U8); // catenate a u8 in format "%hhX"
extern mbs_t mbscatU16(mbs_t* pmbs,
                       uint16_t U16); // catenate a u16 in format "%04X"
extern mbs_t mbscatU32(mbs_t* pmbs,
                       uint32_t U32); // catenate a u32 in format "%08X"
extern mbs_t mbscatU64(mbs_t* pmbs,
                       uint64_t U64); // catenate a u64 in format "%"PRIX64
extern mbs_t mbscato(mbs_t* pmbs, uint8_t o); // catenate an octet as byte value
extern mbs_t
mbscaths(mbs_t* pmbs,
         uint16_t hs); // catenate a host short number as host short number
extern mbs_t
mbscathl(mbs_t* pmbs,
         uint32_t hl); // catenate a host long number as host long nubmer
extern mbs_t mbscathll(
    mbs_t* pmbs,
    uint64_t hll); // catenate a host long long number as host long long number
extern mbs_t
mbscatns(mbs_t* pmbs,
         uint16_t hs); // catenate a host short number as network short number
extern mbs_t
mbscatnl(mbs_t* pmbs,
         uint32_t hl); // catenate a host long number as network long nubmer
extern mbs_t mbscatnll(mbs_t* pmbs,
                       uint64_t hll); // catenate a host long long number as
                                      // network long long number
extern mbs_t mbsaddlen(mbs_t* pmbs, char* s, int len);
extern mbs_t mbsadd(mbs_t* pmbs, char* s);
extern mbs_t mbsaddmbs(mbs_t* pmbs, mbs_t mbs);
extern mbs_t mbsaddvfmt(mbs_t* pmbs, const char* fmt, va_list ap);
extern mbs_t mbsaddfmt(mbs_t* pmbs, const char* fmt, ...);
extern mbs_t mbsjoin(mbs_t* pmbs, int argc, char** argv, char* sep);
extern mbs_t mbssum(mbs_t* pmbs, int argc, char** argv);
extern mbs_t mbstolower(mbs_t mbs);
extern mbs_t mbstoupper(mbs_t mbs);
extern mbs_t mbscapitalize(mbs_t mbs);
extern mbs_t mbsrtrim(mbs_t mbs, char* cset);
extern mbs_t mbsltrim(mbs_t mbs, char* cset);
extern mbs_t mbstrim(mbs_t mbs, char* cset);
extern mbs_t mbsstripwhite(mbs_t mbs);
extern mbs_t mbsrange(mbs_t mbs, int start, int end);
extern mbs_t mbssubstring(mbs_t mbs, int start, int end);
extern mbs_t mbsprecatlen(mbs_t* pmbs, char* s, int len);
extern mbs_t mbsprecat(mbs_t* pmbs, char* s);
extern mbs_t mbsprecatchar(mbs_t* pmbs, char c);
extern mbs_t mbsprecatfmt(mbs_t* pmbs, char* fmt, ...);
extern mbs_t mbsreadline(FILE* fp);
extern mbs_t mbscatstdout(mbs_t* pmbs, char* cmd);
extern mbs_t mbscatstdoutvargs(mbs_t* pmbs, char* fmt, ...);
extern mbs_t mbscatmem(mbs_t* pmbs, void* buf, int len);
extern mbs_t mbsescapejson(mbs_t mbs);
extern mbs_t mbscatescapejson(mbs_t* pmbs, mbs_t mbs);
extern mbs_t mbsprint(mbs_t mbs);
extern void mbsdump(mbs_t mbs);

#endif
