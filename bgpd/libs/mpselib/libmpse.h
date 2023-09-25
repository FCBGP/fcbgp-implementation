#ifndef _LIBMPSE_H_
#define _LIBMPSE_H_

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

/* using char set [0...255] */
#define CHARSET_START       0
#define CHARSET_END         255
#define CHARSET_SIZE        256
#define CHARSET_OFFSET(c)   (c)

#ifndef MIN
#define MIN(x,y)    (((x) > (y)) ? (y) : (x))
#endif
#ifndef MAX
#define MAX(x,y)    (((x) > (y)) ? (x) : (y))
#endif

#define mpse_error(str, arg...) fprintf(stderr, str, ##arg)
#ifdef MPSE_DEBUG
#define mpse_debug(str, arg...) fprintf(stderr, str, ##arg)
#else
#define mpse_debug(str, arg...)
#endif

#define mpse_malloc malloc
#define mpse_free free
#define mpse_realloc realloc

#define MPSE_PATTERN_FLAG_NOCASE    0x0001
#define MPSE_PATTERN_FLAG_OFFSET0   0x0002
#define MPSE_PATTERN_FLAG_OFFSETX   0x0004

enum {
    MPSE_SUCCESS = 0,
    MPSE_ERR_NO_MATCH,
    MPSE_ERR_NO_MEMORY,
    MPSE_ERR_INVAL_PTR,
    MPSE_ERR_INVAL_ALG,
    MPSE_ERR_INVAL_PID,
    MPSE_ERR_ALG_UNSUPPORT,
    MPSE_ERR_ALG_INIT,
    MPSE_ERR_ALG_PREPARE,
    MPSE_ERR_INVAL_PATTERN,
    MPSE_ERR_OVERFLOW_PID,
};

#define MPSE_ALG_INVALID(alg)   (alg >= MPSE_ALG_MAX)
enum {
    MPSE_ALG_AC,
    MPSE_ALG_WM,

    MPSE_ALG_MAX
};

#define MPSE_PATTERN_ID_MAX         0xFFFFFF
#define MPSE_PATTERN_PRIORITY_MAX   0x1F
typedef struct mpse_pattern_st {
    int len;
    uint32_t pid:24,
             nocase:1,
             offset0:1,
             offsetx:1,
             priority:5;
    uint8_t *pattern; /** the origin pattern string */
    uint8_t *lowercase_pattern; /** the lowercase pattern string, if same with pattern, then use the pointer of pattern */
    void *tag;
} mpse_pattern_t;

typedef struct mpse_matcher_st {
    uint32_t matcher_pid;
    uint16_t matcher_start;
    uint16_t matcher_end;
    void *tag;
} mpse_matcher_t;

#define MPSE_MATCHERS_MAX 32

/**
 * we class the output pattern by the priority.
 */
typedef struct mpse_matcher_class_st {
    int n;
    int max;
    mpse_matcher_t *res;
} mpse_matcher_class_t;

typedef struct mpse_matchers_st {
    int allow_repeat:1;
    int allow_priority:1;
    mpse_matcher_class_t *classes;
} mpse_matchers_t;

static inline int mpse_matchers_init(mpse_matchers_t *matchers, int max_matchers, int allow_repeat, int allow_priority)
{
    int n;
    int i, j;

    matchers->allow_repeat = allow_repeat;
    matchers->allow_priority = allow_priority;
    n = (matchers->allow_priority) ? MPSE_PATTERN_PRIORITY_MAX : 1;
    matchers->classes = mpse_malloc(n * sizeof(mpse_matcher_class_t));
    if (matchers->classes == NULL)
        return -ENOMEM;

    for (i=0; i<n; i++) {
        matchers->classes[i].n = 0;
        matchers->classes[i].max = max_matchers;
        matchers->classes[i].res = mpse_malloc(max_matchers * sizeof(mpse_matcher_t));
        if (matchers->classes[i].res == NULL) {
            for (j=0; j<i; j++) {
                mpse_free(matchers->classes[j].res);
            }
            mpse_free(matchers->classes);
            return -ENOMEM;
        }
        memset(matchers->classes[i].res, 0, max_matchers * sizeof(mpse_matcher_t));
    }

    return 0;
}

static inline void mpse_matchers_fini(mpse_matchers_t *matchers)
{
    int i, n;

    if (matchers->classes) {
        n = (matchers->allow_priority) ? MPSE_PATTERN_PRIORITY_MAX : 1;
        for (i=0; i<n; i++) {
            mpse_free(matchers->classes[i].res);
        }
        mpse_free(matchers->classes);
    }
}

static inline void mpse_matchers_flush(mpse_matchers_t *matchers)
{
    int i, n;

    if (matchers->classes) {
        n = (matchers->allow_priority) ? MPSE_PATTERN_PRIORITY_MAX : 1;
        for (i=0; i<n; i++) {
            matchers->classes[i].n = 0;
        }
    }
}

static inline int mpse_matchers_exist(int n, mpse_matcher_t *res, uint32_t pid)
{
    int i;
    mpse_matcher_t *cur;

    for (i=0; i<n; i++) {
        cur = res + i;
        if (cur->matcher_pid == pid) {
            return 1;
        }
    }

    return 0;
}

static inline int mpse_matchers_output(mpse_matchers_t *matchers, int n_matchers, int priority, uint32_t pid, uint16_t start, uint16_t end, void *tag)
{
    mpse_matcher_class_t *classes;

    if (matchers) {
        if (matchers->allow_priority) {
            if (priority < MPSE_PATTERN_PRIORITY_MAX) {
                classes = &matchers->classes[priority];
            } else {
                classes = NULL;
            }
        } else {
            classes = &matchers->classes[0];
        }

        if (classes) {
            if (classes->n < classes->max) {
                if (matchers->allow_repeat || !mpse_matchers_exist(classes->n, classes->res, pid)) {
                    classes->res[classes->n].matcher_pid = pid;
                    classes->res[classes->n].matcher_start = start;
                    classes->res[classes->n].matcher_end = end;
                    classes->res[classes->n].tag = tag;
                    classes->n++;
                }
            }
        }
    }

    n_matchers++;
    return n_matchers;
}

typedef struct mpse_alg_ctx_st {
    void *alg;
    void *data; /* the content of each algorithm such as state table */

    int n_patterns;
    mpse_pattern_t **patterns; /* the pattern pointer array sorted by pid */
} mpse_alg_ctx_t;

typedef struct mpse_alg_st {
    uint16_t alg;
    char *name;
    int (*alg_init)(mpse_alg_ctx_t *ctx);
    int (*alg_prepare)(mpse_alg_ctx_t *ctx);
    int (*alg_search)(mpse_alg_ctx_t *ctx, uint8_t *text, uint16_t len, mpse_matchers_t *matchers, uint16_t flags);
    int (*alg_fini)(mpse_alg_ctx_t *ctx);
    int (*alg_memstat)(mpse_alg_ctx_t *ctx);
} mpse_alg_t;

typedef struct mpse_pattern_node_st {
    mpse_pattern_t *pattern;
    struct mpse_pattern_node_st *next;
} mpse_pattern_node_t;

#define MPSE_PATTERN_HTABLE_SIZE 1024
typedef struct mpse_pattern_htable_st {
    mpse_pattern_node_t *head[MPSE_PATTERN_HTABLE_SIZE];
} mpse_pattern_htable_t;

typedef struct mpse_st {
    mpse_alg_ctx_t *ctx;
    mpse_pattern_htable_t *hash_table;

    uint8_t is_prepared;
} mpse_t;

static inline int mpse_memcmp_nocase(uint8_t *dst, uint8_t *src, uint16_t len)
{
    int i;

    for (i=0; i<len; i++) {
        if (dst[i] != tolower(src[i]))
            return 1;
    }

    return 0;
}

static inline void mpse_memcpy_nocase(uint8_t *dst, uint8_t *src, uint16_t len)
{
    int i;

    for (i=0; i<len; i++) {
        dst[i] = tolower(src[i]);
    }

    return;
}

extern mpse_alg_t ac;

extern int mpse_alg_init(void);
extern int mpse_alg_fini(void);
extern int mpse_alg_register(mpse_alg_t *alg);
extern int mpse_alg_unregister(mpse_alg_t *alg);
extern char *mpse_alg_name(uint16_t alg);
extern char *mpse_alg_name_using(mpse_t *mpse);

extern int mpse_init(void *mpse, uint16_t alg);
extern int mpse_add(void *mpse, uint16_t priority, uint8_t *pattern, uint16_t len, uint16_t flags, uint32_t *pid, void *tag);
extern int mpse_prepare(void *mpse);
extern int mpse_search(void *mpse, uint8_t *text, uint16_t text_len, mpse_matchers_t *matchers, uint16_t flags);
extern int mpse_fini(void *mpse);
extern int mpse_size(void *mpse);
extern int mpse_memstat(void *mpse);

#endif
