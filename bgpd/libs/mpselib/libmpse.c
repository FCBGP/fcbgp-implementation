#include "libmpse.h"

static mpse_alg_t *g_mpse_algs[MPSE_ALG_MAX];

int mpse_alg_init(void)
{
    int i;
    for (i=0; i<MPSE_ALG_MAX; i++) {
        g_mpse_algs[i] = NULL;
    }

    mpse_alg_register(&ac);
    return 0;
}

int mpse_alg_register(mpse_alg_t *alg)
{
    if (MPSE_ALG_INVALID(alg->alg))
        return -MPSE_ERR_INVAL_ALG;

    g_mpse_algs[alg->alg] = alg;
    return 0;
}

int mpse_alg_unregister(mpse_alg_t *alg)
{
    if (MPSE_ALG_INVALID(alg->alg))
        return -MPSE_ERR_INVAL_ALG;

    g_mpse_algs[alg->alg] = NULL;
    return 0;
}

int mpse_alg_fini(void)
{
    int i;
    for (i=0; i<MPSE_ALG_MAX; i++) {
        g_mpse_algs[i] = NULL;
    }

    return 0;
}

char *mpse_alg_name(uint16_t alg)
{
    if (MPSE_ALG_INVALID(alg))
        return NULL;

    if (g_mpse_algs[alg] == NULL)
        return NULL;

    return g_mpse_algs[alg]->name;
}

char *mpse_alg_name_using(mpse_t *mpse)
{
    mpse_alg_t *alg;

    if (mpse->ctx) {
        alg = mpse->ctx->alg;
        if (alg)
            return alg->name;
    }

    return NULL;
}

/**
 * we use JS Hash Function
 */
static uint32_t mpse_pattern_node_hash(uint8_t *pattern, uint16_t len, uint16_t flags, int *has_upper_char, int *none_case_char)
{
    int i;
    uint32_t hval = 1315423911;

    *has_upper_char = 0;
    *none_case_char = 1;
    if (flags & MPSE_PATTERN_FLAG_NOCASE) {
        for (i=0; i<len; i++) {
            hval ^= ((hval << 5) + tolower(pattern[i]) + (hval >> 2));
        }
    } else {
        for (i=0; i<len; i++) {
            if (isupper(pattern[i])) {
                *has_upper_char = 1;
                *none_case_char = 0;
            }
            if (islower(pattern[i])) {
                *none_case_char = 0;
            }
            hval ^= ((hval << 5) + pattern[i] + (hval >> 2));
        }
    }

    return (hval & 0x7FFFFFFF);
}

static uint32_t mpse_pattern_node_match(mpse_pattern_node_t *cur, uint8_t *pattern, uint16_t len, uint16_t flags, uint16_t priority)
{
    mpse_pattern_t *pobj;

    pobj = cur->pattern;
    if (pobj->len != len)
        return 0;

    if (pobj->priority != priority)
        return 0;

    if (flags & MPSE_PATTERN_FLAG_NOCASE) {
        if (pobj->nocase) {
            if (mpse_memcmp_nocase(pobj->pattern, pattern, len))
                return 0;
        } else {
            return 0;
        }
    } else {
        if (pobj->nocase) {
            return 0;
        } else {
            if (memcmp(pobj->pattern, pattern, len))
                return 0;
        }
    }

    if ((flags & MPSE_PATTERN_FLAG_OFFSET0) != pobj->offset0)
        return 0;

    if ((flags & MPSE_PATTERN_FLAG_OFFSETX) != pobj->offsetx)
        return 0;

    return 1;
}

mpse_pattern_t *mpse_pattern_new(void)
{
    mpse_pattern_t *pattern;

    pattern = mpse_malloc(sizeof(mpse_pattern_t));
    if (pattern == NULL)
        return NULL;

    return pattern;
}

void mpse_pattern_destroy(mpse_pattern_t *pattern)
{
    if (pattern) {
        if (pattern->lowercase_pattern) {
            if (pattern->lowercase_pattern != pattern->pattern) {
                mpse_free(pattern->lowercase_pattern);
            }
        }
        if (pattern->pattern) {
            mpse_free(pattern->pattern);
        }
        mpse_free(pattern);
    }
}

static mpse_pattern_htable_t *mpse_htable_new(void)
{
    int i;
    mpse_pattern_htable_t *htable;

    htable = mpse_malloc(sizeof(mpse_pattern_htable_t));
    if (htable == NULL)
        return NULL;

    for (i=0; i<MPSE_PATTERN_HTABLE_SIZE; i++) {
        htable->head[i] = NULL;
    }

    return htable;
}

static mpse_pattern_t *mpse_htable_insert(mpse_pattern_htable_t *htable, uint16_t priority, uint8_t *pattern, uint16_t len, uint16_t flags, void *tag)
{
    uint32_t hval;
    mpse_pattern_t *pobj;
    mpse_pattern_node_t *cur, *tmp;
    mpse_pattern_node_t *new_node;

    int has_upper_char;
    int none_case_char;

    hval = mpse_pattern_node_hash(pattern, len, flags, &has_upper_char, &none_case_char) % MPSE_PATTERN_HTABLE_SIZE;

    cur = htable->head[hval];
    while (cur) {
        if (mpse_pattern_node_match(cur, pattern, len, flags, priority)) {
            printf("pattern %s has existed!\n", pattern);
            return cur->pattern;
        }

        cur = cur->next;
    }

    new_node = mpse_malloc(sizeof(mpse_pattern_node_t));
    if (new_node == NULL)
        return NULL;

    pobj = mpse_pattern_new();
    if (pobj == NULL) {
        mpse_free(new_node);
        return NULL;
    }

    pobj->len = len;
    pobj->tag = tag;
    pobj->pid = MPSE_PATTERN_ID_MAX;
    pobj->priority = priority & 0x1F;
    pobj->nocase = !!(flags & MPSE_PATTERN_FLAG_NOCASE); /**@note must switch to 0/1 */
    pobj->offset0 = !!(flags & MPSE_PATTERN_FLAG_OFFSET0);
    pobj->offsetx = !!(flags & MPSE_PATTERN_FLAG_OFFSETX);
    pobj->pattern = mpse_malloc(len * sizeof(uint8_t));
    if (pobj->pattern == NULL) {
        mpse_free(pobj);
        mpse_free(new_node);
        return NULL;
    }

    if (pobj->nocase) {
        mpse_memcpy_nocase(pobj->pattern, pattern, len);
        pobj->lowercase_pattern = pobj->pattern;
    } else {
        memcpy(pobj->pattern, pattern, len);
        if (has_upper_char) {
            pobj->lowercase_pattern = mpse_malloc(len * sizeof(uint8_t));
            if (pobj->lowercase_pattern == NULL) {
                mpse_free(pobj->pattern);
                mpse_free(pobj);
                mpse_free(new_node);
                return NULL;
            }
            mpse_memcpy_nocase(pobj->lowercase_pattern, pattern, len);
        } else {
            if (none_case_char) {
                pobj->nocase = 1;
            }
            pobj->lowercase_pattern = pobj->pattern;
        }
    }

    new_node->pattern = pobj;
    new_node->next = NULL;

    if (htable->head[hval]) {
        tmp = htable->head[hval];
        htable->head[hval] = new_node;
        new_node->next = tmp;
    } else {
        htable->head[hval] = new_node;
    }

    return pobj;
}

void mpse_array_fini(int n, mpse_pattern_t **array)
{
    int i;

    if (array == NULL)
        return;

    for (i=0; i<n; i++) {
        mpse_pattern_destroy(array[i]);
    }

    mpse_free(array);
}

void mpse_htable_fini(mpse_pattern_htable_t *htable)
{
    int i;
    mpse_pattern_node_t *cur, *tmp;

    for (i=0; i<MPSE_PATTERN_HTABLE_SIZE; i++) {
        cur = htable->head[i];
        while (cur) {
            tmp = cur->next;
            mpse_free(cur);
            cur = tmp;
        }
    }

    mpse_free(htable);
}

int mpse_init(void *mpse, uint16_t alg)
{
    mpse_t *self = (mpse_t *)mpse;

    if (MPSE_ALG_INVALID(alg)) {
        mpse_error("invalid algorithm id %d\n", alg);
        return -MPSE_ERR_INVAL_ALG;
    }

    self->is_prepared = 0;
    self->ctx = mpse_malloc(sizeof(mpse_alg_ctx_t));
    if (self->ctx == NULL)
        return -MPSE_ERR_NO_MEMORY;

    self->ctx->n_patterns = 0;
    self->ctx->patterns = NULL;
    self->ctx->alg = g_mpse_algs[alg];
    self->ctx->data = NULL;

    self->hash_table = mpse_htable_new();
    if (self->hash_table == NULL)
        return -MPSE_ERR_NO_MEMORY;

    return 0;
}

int mpse_add(void *mpse, uint16_t priority, uint8_t *pattern, uint16_t len, uint16_t flags, uint32_t *pid, void *tag)
{
    mpse_pattern_t *pobj;
    mpse_t *self = (mpse_t *)mpse;

    if (len == 0) {
        mpse_error("zero pattern string!\n");
        return -MPSE_ERR_INVAL_PATTERN;
    }

    if (self->ctx->n_patterns >= MPSE_PATTERN_ID_MAX) {
        mpse_error("too many patterns!\n");
        return -MPSE_ERR_OVERFLOW_PID;
    }

    pobj = mpse_htable_insert(self->hash_table, priority, pattern, len, flags, tag);
    if (pobj == NULL) {
        mpse_error("htable insert pattern failed\n");
        return -MPSE_ERR_NO_MEMORY;
    }

    if (pobj->pid != MPSE_PATTERN_ID_MAX) {
        mpse_debug("pattern repeat with %d\n", pobj->pid);
        if (pid) {
            *pid = pobj->pid;
        }

        return 0;
    }

    if (pid) {
        *pid = self->ctx->n_patterns;
    }

    pobj->pid = self->ctx->n_patterns;
    self->ctx->n_patterns++;
    return 0;
}

int mpse_prepare(void *mpse)
{
    int i;
    int ret;
    mpse_alg_t *alg;
    mpse_alg_ctx_t *ctx;
    mpse_pattern_node_t *cur;
    mpse_t *self = (mpse_t *)mpse;

    if (self->is_prepared)
        return 0;

    ctx = self->ctx;
    if (ctx == NULL)
        return -EINVAL;

    if (ctx->n_patterns == 0) {
        self->is_prepared = 1;
        return 0;
    }

    alg = ctx->alg;
    if (alg == NULL)
        return -EINVAL;

    mpse_debug("mpse load %d patterns.\n", ctx->n_patterns);
    ctx->patterns = mpse_malloc(ctx->n_patterns * sizeof(void *));
    if (ctx->patterns == NULL)
        return -MPSE_ERR_NO_MEMORY;

    memset(ctx->patterns, 0, ctx->n_patterns * sizeof(void *));
    for (i=0; i<MPSE_PATTERN_HTABLE_SIZE; i++) {
        cur = self->hash_table->head[i];
        while (cur) {
            ctx->patterns[cur->pattern->pid] = cur->pattern;
            cur = cur->next;
        }
    }

    ret = alg->alg_init(ctx);
    if (ret < 0) {
        mpse_array_fini(self->ctx->n_patterns, self->ctx->patterns);
        ctx->patterns = NULL;
        return -MPSE_ERR_ALG_INIT;
    }

    ret = alg->alg_prepare(ctx);
    if (ret < 0) {
        mpse_array_fini(self->ctx->n_patterns, self->ctx->patterns);
        ctx->patterns = NULL;
        alg->alg_fini(ctx);
        return -MPSE_ERR_ALG_PREPARE;
    }

    self->is_prepared = 1;
    mpse_array_fini(ctx->n_patterns, ctx->patterns);
    ctx->patterns = NULL;
    mpse_htable_fini(self->hash_table);
    self->hash_table = NULL;
    mpse_debug("mpse prepare done!\n");
    return 0;
}

int mpse_search(void *mpse, uint8_t *text, uint16_t text_len, mpse_matchers_t *matchers, uint16_t flags)
{
    mpse_alg_t *alg;
    mpse_t *self = (mpse_t *)mpse;

    if (self->is_prepared == 0)
        return -MPSE_ERR_ALG_PREPARE;

    if (self->ctx == NULL)
        return -MPSE_ERR_INVAL_PTR;

    alg = self->ctx->alg;
    if (alg == NULL)
        return -MPSE_ERR_INVAL_ALG;

    if (alg->alg_search)
        return alg->alg_search(self->ctx, text, text_len, matchers, flags);

    return -MPSE_ERR_INVAL_PTR;
}

int mpse_fini(void *mpse)
{
    mpse_alg_t *alg;
    mpse_t *self = (mpse_t *)mpse;

    if (self->hash_table) {
        mpse_htable_fini(self->hash_table);
        self->hash_table = NULL;
    }

    if (self->ctx) {
        if (self->is_prepared) {
            mpse_array_fini(self->ctx->n_patterns, self->ctx->patterns);
            alg = self->ctx->alg;
            if (alg && alg->alg_fini) {
                alg->alg_fini(self->ctx);
            }

            mpse_free(self->ctx);
            self->ctx = NULL;
        }
    }

    return 0;
}

int mpse_size(void *mpse)
{
    mpse_t *self = (mpse_t *)mpse;

    if (self->ctx) {
        return self->ctx->n_patterns;
    }

    return 0;
}

int mpse_memstat(void *mpse)
{
    int memstat;
    mpse_alg_t *alg;
    mpse_t *self = (mpse_t *)mpse;

    memstat = 0;
    if (self->ctx) {
        memstat += sizeof(mpse_alg_ctx_t);
        alg = self->ctx->alg;
        if (alg) {
            memstat += alg->alg_memstat(self->ctx);
        }
    }

    return memstat;
}

