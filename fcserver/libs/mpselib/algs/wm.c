#include "libmpse.h"

/*bloomfilter is used in hash table*/
typedef struct wm_alg_bloomfilter_st
{
    uint8_t hash_iterations;
    uint32_t (*Hash)(void*, uint16_t, uint8_t, uint32_t);
    uint32_t bitarray_size;
    uint8_t* bitarray;
} wm_alg_bloomfilter_t;

static wm_alg_bloomfilter_t*
wm_alg_bloomfilter_init(uint32_t size, uint8_t iter,
                        uint32_t (*Hash)(void*, uint16_t, uint8_t, uint32_t))
{
    wm_alg_bloomfilter_t* bf = NULL;

    if (size == 0 || iter == 0 || Hash == NULL)
    {
        return NULL;
    }

    bf = mpse_malloc(sizeof(wm_alg_bloomfilter_t));
    if (bf == NULL)
    {
        return NULL;
    }

    memset(bf, 0, sizeof(wm_alg_bloomfilter_t));
    bf->bitarray_size = size;
    bf->hash_iterations = iter;
    bf->Hash = Hash;

    bf->bitarray = mpse_malloc((bf->bitarray_size / 8) + 1);
    if (bf->bitarray == NULL)
    {
        mpse_free(bf);
        return NULL;
    }

    memset(bf->bitarray, 0, (bf->bitarray_size / 8) + 1);
    return bf;
}

static void wm_alg_bloomfilter_fini(wm_alg_bloomfilter_t* bf)
{
    if (bf != NULL)
    {
        if (bf->bitarray != NULL)
            mpse_free(bf->bitarray);
        mpse_free(bf);
    }
}

static int wm_alg_bloomfilter_add(wm_alg_bloomfilter_t* bf, void* data,
                                  uint16_t datalen)
{
    uint8_t iter = 0;
    uint32_t hash = 0;

    if (bf == NULL || data == NULL || datalen == 0)
        return -EINVAL;

    for (iter = 0; iter < bf->hash_iterations; iter++)
    {
        hash = bf->Hash(data, datalen, iter, bf->bitarray_size);
        bf->bitarray[hash / 8] |= (1 << hash % 8);
    }

    return 0;
}

static inline int wm_alg_bloomfilter_test(wm_alg_bloomfilter_t* bf, void* data,
                                          uint16_t datalen)
{
    uint8_t iter = 0;
    uint32_t hash = 0;
    int hit = 1;

    for (iter = 0; iter < bf->hash_iterations; iter++)
    {
        hash = bf->Hash(data, datalen, iter, bf->bitarray_size);
        if (!(bf->bitarray[hash / 8] & (1 << hash % 8)))
        {
            hit = 0;
            break;
        }
    }
    return hit;
}

/*patterns used in wu-manber algorithm*/
typedef struct wm_alg_pattern_st
{
    void* tag;
    uint8_t* cs;
    uint8_t* ci;
    uint16_t prefix_cs;
    uint16_t prefix_ci;
    uint16_t len;
    uint32_t pid : 24, nocase : 1, offset0 : 1, offsetx : 1, priority : 5;
} wm_alg_pattern_t;

/*items in hashtable*/
typedef struct wm_alg_hashitem_st
{
    struct wm_alg_hashitem_st* nxt;
    uint8_t flags;
    uint32_t idx;
} wm_alg_hashitem_t;

/*ctx of wu-manber algorithm*/
typedef struct wm_alg_ctx_st
{
    uint32_t n_patterns;
    uint32_t hash_size;
    uint16_t maxlen;
    uint16_t minlen;
    uint16_t shiftlen;
    uint16_t* shifttable;
    wm_alg_hashitem_t hash1[256];
    wm_alg_hashitem_t** hash;
    wm_alg_bloomfilter_t** bloom;
    uint8_t* pminlen;
    wm_alg_pattern_t** parray;
    uint32_t (*Search)(mpse_alg_ctx_t* mpm_ctx, uint8_t* buf, uint16_t buflen,
                       mpse_matchers_t* matchers, uint16_t flags);
    uint32_t (*MBSearch)(mpse_alg_ctx_t* mpm_ctx, uint8_t* buf, uint16_t buflen,
                         mpse_matchers_t* matchers, uint16_t flags);
} wm_alg_ctx_t;

#define HASH16_SIZE 65536
#define HASH16(a, b) (((a) << 8) | (b))
#define HASH15_SIZE 32768
#define HASH15(a, b) (((a) << 7) | (b))
#define HASH14_SIZE 16384
#define HASH14(a, b) (((a) << 6) | (b))
#define HASH12_SIZE 4096
#define HASH12(a, b) (((a) << 4) | (b))
#define HASH9_SIZE 512
#define HASH9(a, b) (((a) << 1) | (b))

static uint32_t wm_hash_size = 0;
static uint32_t wm_bloom_size = 0;

static uint8_t lowercasetable[256];
/* marco to do the actual lookup */
#define wm_tolower(c) lowercasetable[(c)]

static inline wm_alg_pattern_t* wm_alg_alloc_pattern(mpse_alg_ctx_t* mpm_ctx)
{
    wm_alg_pattern_t* p = mpse_malloc(sizeof(wm_alg_pattern_t));
    if (p == NULL)
        return NULL;
    memset(p, 0, sizeof(wm_alg_pattern_t));

    return p;
}

static inline void wm_alg_free_pattern(mpse_alg_ctx_t* mpm_ctx,
                                       wm_alg_pattern_t* p)
{
    if (p && p->cs && p->cs != p->ci)
    {
        mpse_free(p->cs);
    }

    if (p && p->ci)
    {
        mpse_free(p->ci);
    }

    if (p)
    {
        mpse_free(p);
    }
}

static inline wm_alg_hashitem_t* wm_alg_alloc_hashitem(mpse_alg_ctx_t* mpm_ctx)
{
    wm_alg_hashitem_t* hi = mpse_malloc(sizeof(wm_alg_hashitem_t));
    if (hi == NULL)
        return NULL;
    memset(hi, 0, sizeof(wm_alg_hashitem_t));

    return hi;
}

static void wm_alg_free_hashitem(mpse_alg_ctx_t* mpm_ctx, wm_alg_hashitem_t* hi)
{
    wm_alg_hashitem_t* nxt;
    while (hi)
    {
        nxt = hi->nxt;
        mpse_free(hi);
        hi = nxt;
    }
}

static int build_wm_pattern_from_mpse_pattern(wm_alg_pattern_t* wm_pattern,
                                              mpse_pattern_t* mpse_pattern)
{
    wm_pattern->len = mpse_pattern->len;
    wm_pattern->pid = mpse_pattern->pid;
    wm_pattern->nocase = mpse_pattern->nocase;
    wm_pattern->offset0 = mpse_pattern->offset0;
    wm_pattern->offsetx = mpse_pattern->offsetx;
    wm_pattern->priority = mpse_pattern->priority;
    wm_pattern->tag = mpse_pattern->tag;

    wm_pattern->ci = mpse_malloc(mpse_pattern->len * sizeof(uint8_t));
    if (wm_pattern->ci == NULL)
    {
        mpse_error("pattern malloc failed!\n");
        return -ENOMEM;
    }
    mpse_memcpy_nocase(wm_pattern->ci, mpse_pattern->pattern,
                       mpse_pattern->len);

    if (wm_pattern->nocase)
    {
        wm_pattern->cs = wm_pattern->ci;
    }
    else
    {
        if (memcmp(wm_pattern->ci, mpse_pattern->pattern, mpse_pattern->len) ==
            0)
        {
            wm_pattern->cs = wm_pattern->ci;
        }
        else
        {
            wm_pattern->cs = mpse_malloc(mpse_pattern->len);
            if (wm_pattern->cs == NULL)
            {
                mpse_error("pattern malloc failed!\n");
                return -ENOMEM;
            }

            memcpy(wm_pattern->cs, mpse_pattern->pattern, mpse_pattern->len);
        }
    }
    if (wm_pattern->len > 1)
    {
        wm_pattern->prefix_cs =
            (uint16_t)(*(wm_pattern->cs) + *(wm_pattern->cs + 1));
        wm_pattern->prefix_ci =
            (uint16_t)(*(wm_pattern->ci) + *(wm_pattern->ci + 1));
    }

    return 0;
}

/* init ctx->parray by mpm_ctx->patterns */
static int wm_alg_prepare_pattern_array(mpse_alg_ctx_t* mpm_ctx)
{
    wm_alg_ctx_t* ctx = (wm_alg_ctx_t*)mpm_ctx->data;
    ctx->n_patterns = mpm_ctx->n_patterns;
    ctx->parray = (wm_alg_pattern_t**)mpse_malloc(ctx->n_patterns *
                                                  sizeof(wm_alg_pattern_t*));
    if (ctx->parray == NULL)
    {
        return -ENOMEM;
    }
    memset(ctx->parray, 0, ctx->n_patterns * sizeof(wm_alg_pattern_t*));

    int i, j;
    int count = 0;
    int ret;
    wm_alg_pattern_t* wm_pattern;
    mpse_pattern_t* mpse_pattern;

    for (i = 0; i < mpm_ctx->n_patterns; i++)
    {
        mpse_pattern = mpm_ctx->patterns[i];
        ctx->parray[i] = wm_alg_alloc_pattern(mpm_ctx);
        wm_pattern = ctx->parray[i];
        if (wm_pattern)
        {
            ret = build_wm_pattern_from_mpse_pattern(wm_pattern, mpse_pattern);
            if (ret < 0)
            {
                for (j = 0; j < i + 1; j++)
                {
                    wm_alg_free_pattern(mpm_ctx, ctx->parray[j]);
                }
                mpse_free(ctx->parray);
                return ret;
            }
            count++;
        }
        else
        {
            for (j = 0; j < i; j++)
            {
                wm_alg_free_pattern(mpm_ctx, ctx->parray[j]);
            }
            mpse_free(ctx->parray);
            return ret;
        }
        if (wm_pattern->len > ctx->maxlen)
            ctx->maxlen = wm_pattern->len;
        if (ctx->minlen == 0 ||
            ((ctx->minlen != 0) && (ctx->minlen > wm_pattern->len)))
        {
            ctx->minlen = wm_pattern->len;
        }
    }
    return 0;
}

/* the function that bloomfilter used to filtering text */
static uint32_t wm_alg_bloomfilter_func(void* data, uint16_t datalen,
                                        uint8_t iter, uint32_t hash_size)
{
    uint8_t* d = (uint8_t*)data;
    uint32_t i;
    uint32_t hash = (uint32_t)wm_tolower(*d);

    for (i = 1; i < datalen - 1; i++)
    {
        hash += (wm_tolower((*d++))) ^ i;
    }
    hash <<= (iter + 1);

    hash %= hash_size;
    return hash;
}

/* init wm_alg_ctx_t : hash1, hash, pminlen, bloom */
static int wm_alg_prepare_hashTable(mpse_alg_ctx_t* mpm_ctx)
{
    wm_alg_ctx_t* ctx = (wm_alg_ctx_t*)mpm_ctx->data;
    uint32_t i, j;
    uint32_t idx = 0;
    uint8_t idx8 = 0;

    ctx->hash = (wm_alg_hashitem_t**)mpse_malloc(sizeof(wm_alg_hashitem_t*) *
                                                 ctx->hash_size);
    if (ctx->hash == NULL)
    {
        return -ENOMEM;
    }
    memset(ctx->hash, 0, sizeof(wm_alg_hashitem_t*) * ctx->hash_size);

    ctx->pminlen = (uint8_t*)mpse_malloc(sizeof(uint8_t) * ctx->hash_size);
    if (ctx->pminlen == NULL)
    {
        mpse_free(ctx->hash);
        return -ENOMEM;
    }
    memset(ctx->pminlen, 0, sizeof(uint8_t) * ctx->hash_size);

    for (i = 0; i < mpm_ctx->n_patterns; i++)
    {
        if (ctx->parray[i]->len == 1)
        {
            idx8 = (uint8_t)ctx->parray[i]->ci[0];
            if (ctx->hash1[idx8].flags == 0)
            {
                ctx->hash1[idx8].idx = i;
                ctx->hash1[idx8].flags |= 0x01;
            }
            else
            {
                wm_alg_hashitem_t* hi = wm_alg_alloc_hashitem(mpm_ctx);
                if (hi == NULL)
                {
                    mpse_free(ctx->pminlen);
                    for (j = 0; j < 256; j++)
                        wm_alg_free_hashitem(mpm_ctx, ctx->hash1[j].nxt);
                    for (j = 0; j < ctx->hash_size; j++)
                        wm_alg_free_hashitem(mpm_ctx, ctx->hash[j]);
                    mpse_free(ctx->hash);
                    return -ENOMEM;
                }
                hi->idx = i;
                hi->flags |= 0x01;

                wm_alg_hashitem_t* thi = &ctx->hash1[idx8];
                while (thi->nxt)
                    thi = thi->nxt;
                thi->nxt = hi;
            }
        }
        else
        {
            uint16_t patlen = ctx->shiftlen;

            if (ctx->hash_size == HASH9_SIZE)
                idx = HASH9(ctx->parray[i]->ci[patlen - 1],
                            ctx->parray[i]->ci[patlen - 2]);
            else if (ctx->hash_size == HASH12_SIZE)
                idx = HASH12(ctx->parray[i]->ci[patlen - 1],
                             ctx->parray[i]->ci[patlen - 2]);
            else if (ctx->hash_size == HASH14_SIZE)
                idx = HASH14(ctx->parray[i]->ci[patlen - 1],
                             ctx->parray[i]->ci[patlen - 2]);
            else if (ctx->hash_size == HASH15_SIZE)
                idx = HASH15(ctx->parray[i]->ci[patlen - 1],
                             ctx->parray[i]->ci[patlen - 2]);
            else
                idx = HASH16(ctx->parray[i]->ci[patlen - 1],
                             ctx->parray[i]->ci[patlen - 2]);

            if (ctx->hash[idx] == NULL)
            {
                wm_alg_hashitem_t* hi = wm_alg_alloc_hashitem(mpm_ctx);
                if (hi == NULL)
                {
                    mpse_free(ctx->pminlen);
                    for (j = 0; j < 256; j++)
                        wm_alg_free_hashitem(mpm_ctx, ctx->hash1[j].nxt);
                    for (j = 0; j < ctx->hash_size; j++)
                        wm_alg_free_hashitem(mpm_ctx, ctx->hash[j]);
                    mpse_free(ctx->hash);
                    return -ENOMEM;
                }
                hi->idx = i;
                hi->flags |= 0x01;

                ctx->pminlen[idx] = ctx->parray[i]->len;
                ctx->hash[idx] = hi;
            }
            else
            {
                wm_alg_hashitem_t* hi = wm_alg_alloc_hashitem(mpm_ctx);
                if (hi == NULL)
                {
                    mpse_free(ctx->pminlen);
                    for (j = 0; j < 256; j++)
                        wm_alg_free_hashitem(mpm_ctx, ctx->hash1[j].nxt);
                    for (j = 0; j < ctx->hash_size; j++)
                        wm_alg_free_hashitem(mpm_ctx, ctx->hash[j]);
                    mpse_free(ctx->hash);
                    return -ENOMEM;
                }
                hi->idx = i;
                hi->flags |= 0x01;

                if (ctx->parray[i]->len < ctx->pminlen[idx])
                    ctx->pminlen[idx] = ctx->parray[i]->len;

                wm_alg_hashitem_t* thi = ctx->hash[idx];
                while (thi->nxt)
                    thi = thi->nxt;
                thi->nxt = hi;
            }
        }
    }

    ctx->bloom = (wm_alg_bloomfilter_t**)mpse_malloc(
        sizeof(wm_alg_bloomfilter_t*) * ctx->hash_size);
    if (ctx->bloom == NULL)
    {
        mpse_free(ctx->pminlen);
        for (j = 0; j < 256; j++)
            wm_alg_free_hashitem(mpm_ctx, ctx->hash1[j].nxt);
        for (j = 0; j < ctx->hash_size; j++)
            wm_alg_free_hashitem(mpm_ctx, ctx->hash[j]);
        mpse_free(ctx->hash);
        return -ENOMEM;
    }
    memset(ctx->bloom, 0, sizeof(wm_alg_bloomfilter_t*) * ctx->hash_size);

    uint32_t h;
    for (h = 0; h < ctx->hash_size; h++)
    {
        wm_alg_hashitem_t* hi = ctx->hash[h];
        if (hi == NULL)
            continue;

        ctx->bloom[h] =
            wm_alg_bloomfilter_init(wm_bloom_size, 2, wm_alg_bloomfilter_func);
        if (ctx->bloom[h] == NULL)
        {
            for (j = 0; j < h; j++)
                wm_alg_bloomfilter_fini(ctx->bloom[j]);
            mpse_free(ctx->bloom);
            mpse_free(ctx->pminlen);
            for (j = 0; j < 256; j++)
                wm_alg_free_hashitem(mpm_ctx, ctx->hash1[j].nxt);
            for (j = 0; j < ctx->hash_size; j++)
                wm_alg_free_hashitem(mpm_ctx, ctx->hash[j]);
            mpse_free(ctx->hash);
            return -ENOMEM;
        }
        if (ctx->pminlen[h] > 8)
            ctx->pminlen[h] = 8;

        wm_alg_hashitem_t* thi = hi;
        do
        {
            wm_alg_bloomfilter_add(ctx->bloom[h], ctx->parray[thi->idx]->ci,
                                   ctx->pminlen[h]);
            thi = thi->nxt;
        } while (thi != NULL);
    }

    return 0;
}

/*create shifttable*/
static int wm_alg_prepare_shiftTable(mpse_alg_ctx_t* mpm_ctx)
{
    wm_alg_ctx_t* ctx = (wm_alg_ctx_t*)mpm_ctx->data;

    uint16_t shift = 0, k = 0, idx = 0;
    uint32_t i = 0;

    uint16_t smallest = ctx->minlen;
    if (smallest > 255)
        smallest = 255;
    if (smallest < 2)
        smallest = 2;

    ctx->shiftlen = smallest;

    ctx->shifttable = mpse_malloc(sizeof(uint16_t) * ctx->hash_size);
    if (ctx->shifttable == NULL)
    {
        return -ENOMEM;
    }

    for (i = 0; i < ctx->hash_size; i++)
    {
        ctx->shifttable[i] = ctx->shiftlen;
    }

    for (i = 0; i < mpm_ctx->n_patterns; i++)
    {
        if (ctx->parray[i]->len == 1)
            continue;

        for (k = 0; k < 256; k++)
        {
            shift = ctx->shiftlen - 1;
            if (shift > 255)
                shift = 255;

            if (ctx->hash_size == HASH9_SIZE)
            {
                idx = HASH9(ctx->parray[i]->ci[0], (uint8_t)k);
            }
            else if (ctx->hash_size == HASH12_SIZE)
            {
                idx = HASH12(ctx->parray[i]->ci[0], (uint8_t)k);
            }
            else if (ctx->hash_size == HASH14_SIZE)
            {
                idx = HASH14(ctx->parray[i]->ci[0], (uint8_t)k);
            }
            else if (ctx->hash_size == HASH15_SIZE)
            {
                idx = HASH15(ctx->parray[i]->ci[0], (uint8_t)k);
            }
            else
            {
                idx = HASH16(ctx->parray[i]->ci[0], (uint8_t)k);
            }
            if (shift < ctx->shifttable[idx])
            {
                ctx->shifttable[idx] = shift;
            }
        }

        for (k = 0; k < ctx->shiftlen - 1; k++)
        {
            shift = (ctx->shiftlen - 2 - k);
            if (shift > 255)
                shift = 255;

            if (ctx->hash_size == HASH9_SIZE)
            {
                idx = HASH9(ctx->parray[i]->ci[k + 1], ctx->parray[i]->ci[k]);
            }
            else if (ctx->hash_size == HASH12_SIZE)
            {
                idx = HASH12(ctx->parray[i]->ci[k + 1], ctx->parray[i]->ci[k]);
            }
            else if (ctx->hash_size == HASH14_SIZE)
            {
                idx = HASH14(ctx->parray[i]->ci[k + 1], ctx->parray[i]->ci[k]);
            }
            else if (ctx->hash_size == HASH15_SIZE)
            {
                idx = HASH15(ctx->parray[i]->ci[k + 1], ctx->parray[i]->ci[k]);
            }
            else
            {
                idx = HASH16(ctx->parray[i]->ci[k + 1], ctx->parray[i]->ci[k]);
            }
            if (shift < ctx->shifttable[idx])
            {
                ctx->shifttable[idx] = shift;
            }
        }
    }

    return 0;
}

static uint32_t wm_alg_search2hash9(mpse_alg_ctx_t* mpm_ctx, uint8_t* buf,
                                    uint16_t buflen, mpse_matchers_t* matchers,
                                    uint16_t flags)
{
    wm_alg_ctx_t* ctx = (wm_alg_ctx_t*)mpm_ctx->data;
    uint32_t cnt = 0;
    uint8_t* bufend = buf + buflen - 1;
    uint8_t* bufstart = buf;
    uint16_t sl = ctx->shiftlen;
    uint16_t h;
    uint8_t shift;
    wm_alg_hashitem_t *thi, *hi;
    wm_alg_pattern_t* p;
    uint16_t prefixci_buf;
    uint16_t prefixcs_buf;
    uint16_t start, end;

    if (buflen == 0)
        return 0;

    buf += (sl - 1);

    while (buf <= bufend)
    {
        h = HASH9(wm_tolower(*buf), (wm_tolower(*(buf - 1))));
        shift = ctx->shifttable[h];

        if (shift == 0)
        {

            hi = ctx->hash[h];
            if (hi != NULL)
            {
                if (ctx->bloom[h] != NULL)
                {
                    if ((bufend - (buf - sl)) < ctx->pminlen[h])
                    {
                        goto skip_loop;
                    }
                    else
                    {
                        if (wm_alg_bloomfilter_test(ctx->bloom[h], buf - sl + 1,
                                                    ctx->pminlen[h]) == 0)
                        {
                            goto skip_loop;
                        }
                    }
                }

                prefixci_buf = (uint16_t)(wm_tolower(*(buf - sl + 1)) +
                                          wm_tolower(*(buf - sl + 2)));
                prefixcs_buf = (uint16_t)(*(buf - sl + 1) + *(buf - sl + 2));

                for (thi = hi; thi != NULL; thi = thi->nxt)
                {
                    p = ctx->parray[thi->idx];

                    if (p->nocase)
                    {
                        if (p->prefix_ci != prefixci_buf ||
                            p->len > (bufend - (buf - sl)))
                            continue;

                        if (mpse_memcmp_nocase(p->ci, buf - sl + 1, p->len) ==
                            0)
                        {
                            start = (uint16_t)(buf - sl + 1 - bufstart);
                            end = start + p->len - 1;
                            if (p->offset0)
                                if (start != 0)
                                    continue;
                            if (p->offsetx)
                                if (end != buflen - 1)
                                    continue;
                            cnt = mpse_matchers_output(matchers, cnt,
                                                       p->priority, p->pid,
                                                       start, end, p->tag);
                        }
                    }
                    else
                    {
                        if (p->prefix_cs != prefixcs_buf ||
                            p->len > (bufend - (buf - sl)))
                            continue;
                        if (memcmp(p->cs, buf - sl + 1, p->len) == 0)
                        {
                            start = (uint16_t)(buf - sl + 1 - bufstart);
                            end = start + p->len - 1;
                            if (p->offset0)
                                if (start != 0)
                                    continue;
                            if (p->offsetx)
                                if (end != buflen - 1)
                                    continue;
                            cnt = mpse_matchers_output(matchers, cnt,
                                                       p->priority, p->pid,
                                                       start, end, p->tag);
                        }
                    }
                }
            }
        skip_loop:
            shift = 1;
        }
        buf += shift;
    }
    return cnt;
}

static uint32_t wm_alg_search2hash12(mpse_alg_ctx_t* mpm_ctx, uint8_t* buf,
                                     uint16_t buflen, mpse_matchers_t* matchers,
                                     uint16_t flags)
{
    wm_alg_ctx_t* ctx = (wm_alg_ctx_t*)mpm_ctx->data;
    uint32_t cnt = 0;
    uint8_t* bufend = buf + buflen - 1;
    uint8_t* bufstart = buf;
    uint16_t sl = ctx->shiftlen;
    uint16_t h;
    uint8_t shift;
    wm_alg_hashitem_t *thi, *hi;
    wm_alg_pattern_t* p;
    uint16_t prefixci_buf;
    uint16_t prefixcs_buf;
    uint16_t start, end;

    if (buflen == 0)
        return 0;

    buf += (sl - 1);

    while (buf <= bufend)
    {
        h = HASH12(wm_tolower(*buf), (wm_tolower(*(buf - 1))));
        shift = ctx->shifttable[h];

        if (shift == 0)
        {
            hi = ctx->hash[h];
            if (hi != NULL)
            {
                if (ctx->bloom[h] != NULL)
                {
                    if ((bufend - (buf - sl)) < ctx->pminlen[h])
                    {
                        goto skip_loop;
                    }
                    else
                    {
                        if (wm_alg_bloomfilter_test(ctx->bloom[h], buf - sl + 1,
                                                    ctx->pminlen[h]) == 0)
                        {
                            goto skip_loop;
                        }
                    }
                }

                prefixci_buf = (uint16_t)(wm_tolower(*(buf - sl + 1)) +
                                          wm_tolower(*(buf - sl + 2)));
                prefixcs_buf = (uint16_t)(*(buf - sl + 1) + *(buf - sl + 2));
                for (thi = hi; thi != NULL; thi = thi->nxt)
                {
                    p = ctx->parray[thi->idx];

                    if (p->nocase)
                    {
                        if (p->prefix_ci != prefixci_buf ||
                            p->len > (bufend - (buf - sl)))
                            continue;

                        if (mpse_memcmp_nocase(p->ci, buf - sl + 1, p->len) ==
                            0)
                        {
                            start = (uint16_t)(buf - sl + 1 - bufstart);
                            end = start + p->len - 1;
                            if (p->offset0)
                                if (start != 0)
                                    continue;
                            if (p->offsetx)
                                if (end != buflen - 1)
                                    continue;
                            cnt = mpse_matchers_output(matchers, cnt,
                                                       p->priority, p->pid,
                                                       start, end, p->tag);
                        }
                    }
                    else
                    {
                        if (p->prefix_cs != prefixcs_buf ||
                            p->len > (bufend - (buf - sl)))
                            continue;
                        if (memcmp(p->cs, buf - sl + 1, p->len) == 0)
                        {
                            start = (uint16_t)(buf - sl + 1 - bufstart);
                            end = start + p->len - 1;
                            if (p->offset0)
                                if (start != 0)
                                    continue;
                            if (p->offsetx)
                                if (end != buflen - 1)
                                    continue;
                            cnt = mpse_matchers_output(matchers, cnt,
                                                       p->priority, p->pid,
                                                       start, end, p->tag);
                        }
                    }
                }
            }
        skip_loop:
            shift = 1;
        }
        buf += shift;
    }

    return cnt;
}

static uint32_t wm_alg_search2hash14(mpse_alg_ctx_t* mpm_ctx, uint8_t* buf,
                                     uint16_t buflen, mpse_matchers_t* matchers,
                                     uint16_t flags)
{
    wm_alg_ctx_t* ctx = (wm_alg_ctx_t*)mpm_ctx->data;
    uint32_t cnt = 0;
    uint8_t* bufend = buf + buflen - 1;
    uint8_t* bufstart = buf;
    uint16_t sl = ctx->shiftlen;
    uint16_t h;
    uint8_t shift;
    wm_alg_hashitem_t *thi, *hi;
    wm_alg_pattern_t* p;
    uint16_t prefixci_buf;
    uint16_t prefixcs_buf;
    uint16_t start, end;

    if (buflen == 0)
        return 0;

    buf += (sl - 1);

    while (buf <= bufend)
    {
        h = HASH14(wm_tolower(*buf), (wm_tolower(*(buf - 1))));
        shift = ctx->shifttable[h];

        if (shift == 0)
        {
            hi = ctx->hash[h];
            if (hi != NULL)
            {
                if (ctx->bloom[h] != NULL)
                {

                    if ((bufend - (buf - sl)) < ctx->pminlen[h])
                    {
                        goto skip_loop;
                    }
                    else
                    {

                        if (wm_alg_bloomfilter_test(ctx->bloom[h], buf - sl + 1,
                                                    ctx->pminlen[h]) == 0)
                        {
                            goto skip_loop;
                        }
                    }
                }

                prefixci_buf = (uint16_t)(wm_tolower(*(buf - sl + 1)) +
                                          wm_tolower(*(buf - sl + 2)));
                prefixcs_buf = (uint16_t)(*(buf - sl + 1) + *(buf - sl + 2));
                for (thi = hi; thi != NULL; thi = thi->nxt)
                {
                    p = ctx->parray[thi->idx];

                    if (p->nocase)
                    {
                        if (p->prefix_ci != prefixci_buf ||
                            p->len > (bufend - (buf - sl)))
                            continue;

                        if (mpse_memcmp_nocase(p->ci, buf - sl + 1, p->len) ==
                            0)
                        {
                            start = (uint16_t)(buf - sl + 1 - bufstart);
                            end = start + p->len - 1;
                            if (p->offset0)
                                if (start != 0)
                                    continue;
                            if (p->offsetx)
                                if (end != buflen - 1)
                                    continue;
                            cnt = mpse_matchers_output(matchers, cnt,
                                                       p->priority, p->pid,
                                                       start, end, p->tag);
                        }
                    }
                    else
                    {
                        if (p->prefix_cs != prefixcs_buf ||
                            p->len > (bufend - (buf - sl)))
                            continue;
                        if (memcmp(p->cs, buf - sl + 1, p->len) == 0)
                        {
                            start = (uint16_t)(buf - sl + 1 - bufstart);
                            end = start + p->len - 1;
                            if (p->offset0)
                                if (start != 0)
                                    continue;
                            if (p->offsetx)
                                if (end != buflen - 1)
                                    continue;
                            cnt = mpse_matchers_output(matchers, cnt,
                                                       p->priority, p->pid,
                                                       start, end, p->tag);
                        }
                    }
                }
            }
        skip_loop:
            shift = 1;
        }
        buf += shift;
    }

    return cnt;
}

static uint32_t wm_alg_search2hash15(mpse_alg_ctx_t* mpm_ctx, uint8_t* buf,
                                     uint16_t buflen, mpse_matchers_t* matchers,
                                     uint16_t flags)
{
    wm_alg_ctx_t* ctx = (wm_alg_ctx_t*)mpm_ctx->data;
    uint32_t cnt = 0;
    uint8_t* bufend = buf + buflen - 1;
    uint8_t* bufstart = buf;
    uint16_t sl = ctx->shiftlen;
    uint16_t h;
    uint8_t shift;
    wm_alg_hashitem_t *thi, *hi;
    wm_alg_pattern_t* p;
    uint16_t prefixci_buf;
    uint16_t prefixcs_buf;
    uint16_t start, end;

    if (buflen == 0)
        return 0;

    buf += (sl - 1);

    while (buf <= bufend)
    {
        h = HASH15(wm_tolower(*buf), (wm_tolower(*(buf - 1))));
        shift = ctx->shifttable[h];

        if (shift == 0)
        {
            hi = ctx->hash[h];
            if (hi != NULL)
            {
                if (ctx->bloom[h] != NULL)
                {

                    if ((bufend - (buf - sl)) < ctx->pminlen[h])
                    {
                        goto skip_loop;
                    }
                    else
                    {
                        if (wm_alg_bloomfilter_test(ctx->bloom[h], buf - sl + 1,
                                                    ctx->pminlen[h]) == 0)
                        {
                            goto skip_loop;
                        }
                    }
                }

                prefixci_buf = (uint16_t)(wm_tolower(*(buf - sl + 1)) +
                                          wm_tolower(*(buf - sl + 2)));
                prefixcs_buf = (uint16_t)(*(buf - sl + 1) + *(buf - sl + 2));
                for (thi = hi; thi != NULL; thi = thi->nxt)
                {
                    p = ctx->parray[thi->idx];

                    if (p->nocase)
                    {
                        if (p->prefix_ci != prefixci_buf ||
                            p->len > (bufend - (buf - sl)))
                            continue;

                        if (mpse_memcmp_nocase(p->ci, buf - sl + 1, p->len) ==
                            0)
                        {
                            start = (uint16_t)(buf - sl + 1 - bufstart);
                            end = start + p->len - 1;
                            if (p->offset0)
                            {
                                if (start != 0)
                                {
                                    continue;
                                }
                            }
                            if (p->offsetx)
                            {
                                if (end != buflen - 1)
                                {
                                    continue;
                                }
                            }
                            cnt = mpse_matchers_output(matchers, cnt,
                                                       p->priority, p->pid,
                                                       start, end, p->tag);
                        }
                    }
                    else
                    {
                        if (p->prefix_cs != prefixcs_buf ||
                            p->len > (bufend - (buf - sl)))
                            continue;
                        if (memcmp(p->cs, buf - sl + 1, p->len) == 0)
                        {
                            start = (uint16_t)(buf - sl + 1 - bufstart);
                            end = start + p->len - 1;
                            if (p->offset0)
                            {
                                if (start != 0)
                                {
                                    continue;
                                }
                            }
                            if (p->offsetx)
                            {
                                if (end != buflen - 1)
                                {
                                    continue;
                                }
                            }
                            cnt = mpse_matchers_output(matchers, cnt,
                                                       p->priority, p->pid,
                                                       start, end, p->tag);
                        }
                    }
                }
            }
        skip_loop:
            shift = 1;
        }
        buf += shift;
    }

    return cnt;
}

static uint32_t wm_alg_search2hash16(mpse_alg_ctx_t* mpm_ctx, uint8_t* buf,
                                     uint16_t buflen, mpse_matchers_t* matchers,
                                     uint16_t flags)
{
    wm_alg_ctx_t* ctx = (wm_alg_ctx_t*)mpm_ctx->data;
    uint32_t cnt = 0;
    uint32_t count_shift_hit = 0;
    uint32_t count_bloomfilter_hit = 0;
    uint32_t count_prefix_hit = 0;
    uint32_t count_compare_hit = 0;
    uint8_t* bufend = buf + buflen - 1;
    uint8_t* bufstart = buf;
    uint16_t sl = ctx->shiftlen;
    uint16_t h;
    uint8_t shift;
    wm_alg_hashitem_t *thi, *hi;
    wm_alg_pattern_t* p;
    uint16_t prefixci_buf;
    uint16_t prefixcs_buf;
    uint16_t start, end;

    if (buflen == 0)
        return 0;

    buf += (sl - 1);

    while (buf <= bufend)
    {
        h = HASH16(wm_tolower(*buf), (wm_tolower(*(buf - 1))));
        shift = ctx->shifttable[h];
        if (shift != 0)
        {
            count_shift_hit++;
        }
        if (shift == 0)
        {
            hi = ctx->hash[h];
            if (hi != NULL)
            {
                if (ctx->bloom[h] != NULL)
                {
                    if ((bufend - (buf - sl)) < ctx->pminlen[h])
                    {
                        goto skip_loop;
                    }
                    else
                    {
                        count_bloomfilter_hit++;
                        if (wm_alg_bloomfilter_test(ctx->bloom[h], buf - sl + 1,
                                                    ctx->pminlen[h]) == 0)
                        {
                            goto skip_loop;
                        }
                    }
                }

                prefixci_buf = (uint16_t)(wm_tolower(*(buf - sl + 1)) +
                                          wm_tolower(*(buf - sl + 2)));
                prefixcs_buf = (uint16_t)(*(buf - sl + 1) + *(buf - sl + 2));
                for (thi = hi; thi != NULL; thi = thi->nxt)
                {
                    p = ctx->parray[thi->idx];

                    if (p->nocase)
                    {
                        count_prefix_hit++;
                        if (p->prefix_ci != prefixci_buf ||
                            p->len > (bufend - (buf - sl)))
                        {
                            continue;
                        }
                        count_compare_hit++;
                        if (mpse_memcmp_nocase(p->ci, buf - sl + 1, p->len) ==
                            0)
                        {
                            start = (uint16_t)(buf - sl + 1 - bufstart);
                            end = start + p->len - 1;
                            if (p->offset0)
                                if (start != 0)
                                    continue;
                            if (p->offsetx)
                                if (end != buflen - 1)
                                    continue;
                            cnt = mpse_matchers_output(matchers, cnt,
                                                       p->priority, p->pid,
                                                       start, end, p->tag);
                        }
                    }
                    else
                    {
                        count_prefix_hit++;
                        if (p->prefix_cs != prefixcs_buf ||
                            p->len > (bufend - (buf - sl)))
                        {
                            continue;
                        }
                        count_compare_hit++;
                        if (memcmp(p->cs, buf - sl + 1, p->len) == 0)
                        {
                            start = (uint16_t)(buf - sl + 1 - bufstart);
                            end = start + p->len - 1;
                            if (p->offset0)
                                if (start != 0)
                                    continue;
                            if (p->offsetx)
                                if (end != buflen - 1)
                                    continue;
                            cnt = mpse_matchers_output(matchers, cnt,
                                                       p->priority, p->pid,
                                                       start, end, p->tag);
                        }
                    }
                }
            }
        skip_loop:
            shift = 1;
        }
        buf += shift;
    }

    return cnt;
}

static uint32_t wm_alg_search1(mpse_alg_ctx_t* mpm_ctx, uint8_t* buf,
                               uint16_t buflen, mpse_matchers_t* matchers,
                               uint16_t flags)
{
    wm_alg_ctx_t* ctx = (wm_alg_ctx_t*)mpm_ctx->data;
    uint8_t* bufstart = buf;
    uint8_t* bufend = buf + buflen - 1;
    uint32_t cnt = 0;
    wm_alg_pattern_t* p;
    wm_alg_hashitem_t *thi, *hi;
    uint16_t start, end;

    if (buflen == 0)
        return 0;

    if (ctx->minlen == 1)
    {
        while (buf <= bufend)
        {
            uint8_t h = wm_tolower(*buf);
            hi = &ctx->hash1[h];

            if (hi->flags & 0x01)
            {
                for (thi = hi; thi != NULL; thi = thi->nxt)
                {
                    p = ctx->parray[thi->idx];

                    if (p->len != 1)
                        continue;

                    if (p->nocase)
                    {
                        if (wm_tolower(*buf) == p->ci[0])
                        {
                            start = (uint16_t)(buf - bufstart);
                            end = start;
                            if (p->offset0)
                                if (start != 0)
                                    continue;
                            if (p->offsetx)
                                if (end != buflen - 1)
                                    continue;
                            cnt = mpse_matchers_output(matchers, cnt,
                                                       p->priority, p->pid,
                                                       start, end, p->tag);
                        }
                    }
                    else
                    {
                        if (*buf == p->cs[0])
                        {
                            start = (uint16_t)(buf - bufstart);
                            end = start;
                            if (p->offset0)
                                if (start != 0)
                                    continue;
                            if (p->offsetx)
                                if (end != buflen - 1)
                                    continue;
                            cnt = mpse_matchers_output(matchers, cnt,
                                                       p->priority, p->pid,
                                                       start, end, p->tag);
                        }
                    }
                }
            }
            buf += 1;
        }
    }
    if (ctx->maxlen > 1)
    {
        cnt += ctx->MBSearch(mpm_ctx, bufstart, buflen, matchers, flags);
    }
    return cnt;
}

/*prepare patterns for wu-manber algorithm*/
static int wm_alg_prepare(mpse_alg_ctx_t* mpm_ctx)
{
    int i;
    int ret;
    wm_alg_ctx_t* ctx = mpm_ctx->data;

    /* convert 'mpse_pattern_t'  to  'wm_alg_pattern_t' */
    ret = wm_alg_prepare_pattern_array(mpm_ctx);
    if (ret < 0)
        return ret;

    /* init 'hash_size' by 'n_patterns' */
    if (ctx->hash_size == 0)
    {
        if (mpm_ctx->n_patterns < 50)
        {
            ctx->hash_size = HASH9_SIZE;
        }
        else if (mpm_ctx->n_patterns < 300)
        {
            ctx->hash_size = HASH12_SIZE;
        }
        else if (mpm_ctx->n_patterns < 1200)
        {
            ctx->hash_size = HASH14_SIZE;
        }
        else if (mpm_ctx->n_patterns < 2400)
        {
            ctx->hash_size = HASH15_SIZE;
        }
        else
        {
            ctx->hash_size = HASH16_SIZE;
        }
    }

    /* if ret<0 ,free 'parray' */
    ret = wm_alg_prepare_shiftTable(mpm_ctx);
    if (ret < 0)
    {
        for (i = 0; i < ctx->n_patterns; i++)
            wm_alg_free_pattern(mpm_ctx, ctx->parray[i]);
        mpse_free(ctx->parray);
        return ret;
    }

    /* if ret<0 , free 'parray' and 'shifttable' */
    ret = wm_alg_prepare_hashTable(mpm_ctx);
    if (ret < 0)
    {
        for (i = 0; i < ctx->n_patterns; i++)
            wm_alg_free_pattern(mpm_ctx, ctx->parray[i]);
        mpse_free(ctx->parray);
        mpse_free(ctx->shifttable);
        return ret;
    }

    if (ctx->hash_size == HASH9_SIZE)
    {
        ctx->MBSearch = wm_alg_search2hash9;
        ctx->Search = wm_alg_search2hash9;
    }
    else if (ctx->hash_size == HASH12_SIZE)
    {
        ctx->MBSearch = wm_alg_search2hash12;
        ctx->Search = wm_alg_search2hash12;
    }
    else if (ctx->hash_size == HASH14_SIZE)
    {
        ctx->MBSearch = wm_alg_search2hash14;
        ctx->Search = wm_alg_search2hash14;
    }
    else if (ctx->hash_size == HASH15_SIZE)
    {
        ctx->MBSearch = wm_alg_search2hash15;
        ctx->Search = wm_alg_search2hash15;
    }
    else
    {
        ctx->MBSearch = wm_alg_search2hash16;
        ctx->Search = wm_alg_search2hash16;
    }

    if (ctx->minlen == 1)
    {
        ctx->Search = wm_alg_search1;
    }

    return 0;
}

static int wm_alg_search(mpse_alg_ctx_t* mpm_ctx, uint8_t* buf, uint16_t buflen,
                         mpse_matchers_t* matchers, uint16_t flags)
{
    wm_alg_ctx_t* ctx = (wm_alg_ctx_t*)mpm_ctx->data;
    return ctx->Search(mpm_ctx, buf, buflen, matchers, flags);
}

#define HASHSIZE_LOW 4096
#define BLOOMSIZE_MEDIUM 1024

void wm_alg_getconfig()
{
    wm_hash_size = HASHSIZE_LOW;
    wm_bloom_size = BLOOMSIZE_MEDIUM;
}

static int wm_alg_init(mpse_alg_ctx_t* mpm_ctx)
{
    int c = 0;

    for (c = 0; c < 255; c++)
    {
        if (c >= 'A' && c <= 'Z')
            lowercasetable[c] = (c + ('a' - 'A'));
        else
            lowercasetable[c] = c;
    }

    mpm_ctx->data = mpse_malloc(sizeof(wm_alg_ctx_t));
    if (mpm_ctx->data == NULL)
        return -ENOMEM;

    memset(mpm_ctx->data, 0, sizeof(wm_alg_ctx_t));

    if (wm_hash_size == 0)
        wm_alg_getconfig();

    return 0;
}

static int wm_alg_fini(mpse_alg_ctx_t* mpm_ctx)
{
    int i;
    wm_alg_ctx_t* ctx = (wm_alg_ctx_t*)mpm_ctx->data;
    if (ctx == NULL)
        return 0;

    if (ctx->parray)
    {
        for (i = 0; i < mpm_ctx->n_patterns; i++)
        {
            if (ctx->parray[i] != NULL)
            {
                wm_alg_free_pattern(mpm_ctx, ctx->parray[i]);
            }
        }

        mpse_free(ctx->parray);
    }

    if (ctx->bloom)
    {
        for (i = 0; i < ctx->hash_size; i++)
        {
            if (ctx->bloom[i] == NULL)
                continue;

            wm_alg_bloomfilter_fini(ctx->bloom[i]);
        }

        mpse_free(ctx->bloom);
    }

    if (ctx->hash)
    {
        for (i = 0; i < ctx->hash_size; i++)
        {
            if (ctx->hash[i] == NULL)
                continue;

            wm_alg_free_hashitem(mpm_ctx, ctx->hash[i]);
        }

        mpse_free(ctx->hash);
    }

    if (ctx->shifttable)
    {
        mpse_free(ctx->shifttable);
    }

    if (ctx->pminlen)
    {
        mpse_free(ctx->pminlen);
    }

    mpse_free(mpm_ctx->data);

    return 0;
}

static int wm_alg_memstat(mpse_alg_ctx_t* mpm_ctx)
{
    int i;
    int memstat = 0;
    wm_alg_ctx_t* ctx;
    wm_alg_hashitem_t* temp;
    wm_alg_bloomfilter_t* temp_bloomfilter;
    wm_alg_pattern_t* temp_pattern;

    ctx = (wm_alg_ctx_t*)mpm_ctx->data;
    if (ctx)
    {
        memstat += sizeof(wm_alg_ctx_t);

        /* calculate shifttable */
        if (ctx->shifttable)
        {
            memstat += sizeof(uint16_t) * ctx->hash_size;
        }

        /* calculate pminlen table */
        if (ctx->pminlen)
        {
            memstat += sizeof(uint8_t) * ctx->hash_size;
        }

        /* calculate hash table */
        if (ctx->hash)
        {
            memstat += ctx->hash_size * sizeof(wm_alg_hashitem_t*);
            for (i = 0; i < ctx->hash_size; i++)
            {
                temp = ctx->hash[i];
                while (temp)
                {
                    memstat += sizeof(wm_alg_hashitem_t);
                    temp = temp->nxt;
                }
            }
        }

        /* calculate hash1 table */
        for (i = 0; i < 256; i++)
        {
            temp = &ctx->hash1[i];
            while (temp->nxt)
            {
                temp = temp->nxt;
                memstat += sizeof(wm_alg_hashitem_t);
            }
        }

        /* calculate bloomfilter */
        if (ctx->bloom)
        {
            memstat += ctx->hash_size * sizeof(wm_alg_bloomfilter_t*);
            for (i = 0; i < ctx->hash_size; i++)
            {
                temp_bloomfilter = ctx->bloom[i];
                if (temp_bloomfilter)
                {
                    memstat += sizeof(wm_alg_bloomfilter_t);
                    if (temp_bloomfilter->bitarray)
                    {
                        memstat += temp_bloomfilter->bitarray_size;
                    }
                }
            }
        }

        /* calculate pattern array */
        if (ctx->parray)
        {
            memstat += ctx->n_patterns * sizeof(wm_alg_pattern_t*);
            for (i = 0; i < ctx->n_patterns; i++)
            {
                temp_pattern = ctx->parray[i];
                if (temp_pattern)
                {
                    memstat += sizeof(wm_alg_pattern_t);
                    if (temp_pattern->ci)
                        memstat += temp_pattern->len * sizeof(uint8_t);
                    if (temp_pattern->cs &&
                        (temp_pattern->cs != temp_pattern->ci))
                        memstat += temp_pattern->len * sizeof(uint8_t);
                }
            }
        }
    }

    return memstat;
}

mpse_alg_t wm = {
    .alg = MPSE_ALG_WM,
    .name = "WM",
    .alg_init = wm_alg_init,
    .alg_prepare = wm_alg_prepare,
    .alg_fini = wm_alg_fini,
    .alg_search = wm_alg_search,
    .alg_memstat = wm_alg_memstat,
};
