#include "libmpse.h"

/**
 * @file ac.c
 * @author liaoxf<liaofei1128@163.com>
 * @brief the Aho-Corasick MPM algorithm
 *
 * - Uses the delta table for calculating transitions, instead of having
 *   separate goto and failure transitions.
 * - If we cross 2 ** 16 states, we use 4 bytes in the transition table
 *   to hold each state, otherwise we use 2 bytes.
 * - This version of the MPM is heavy on memory, but it performs well.
 *   If you can fit the ruleset with this mpm on your box without hitting
 *   swap, this is the MPM to go for.
 * - Test case-senstive patterns if they have any ascii chars.  If they
 *   don't treat them as nocase.
 *
 * @see Alfred V. Aho and Margaret J. Corasick, Efficient String Matching: An Aid to Bibliographic Search
 */

#define AC_STATE_FAIL -1

typedef int int_array_t[CHARSET_SIZE];

typedef uint16_t uint16_array_t[CHARSET_SIZE];
typedef uint32_t uint32_array_t[CHARSET_SIZE];

/**
 * @brief using this structure in the algorithm instead of mpse_pattern_t,
 * we can save 8+len bytes for each pattern.
 */
typedef struct ac_alg_pattern_st {
    uint16_t len;
    uint16_t offset0:1,
             offsetx:1,
             priority:5,
             res:9;
    /* just save the origin string here, the lowercase one had been saved in the state table.
     * if not null, after AC matching, need to match with the it again
     * */
    uint8_t *pattern;
    void *tag;
} ac_alg_pattern_t;

typedef struct ac_alg_output_pid_st {
    uint32_t pid:24,
             nocase:1,
             offset0:1,
             offsetx:1,
             priority:5;
} ac_alg_output_pid_t;

typedef struct ac_alg_output_st {
    uint32_t n_pids;
    ac_alg_output_pid_t *pids; /** the pid array sort by priority */
} ac_alg_output_t;

typedef struct ac_alg_ctx_st {
    int n_states;
    int n_patterns;
    union {
        void *table;
        uint16_array_t *u16_table;
        uint32_array_t *u32_table;
    } state;
    int_array_t *goto_table;
    int *failure_table;
    ac_alg_output_t *output_table;
    ac_alg_pattern_t *pattern_table;
} ac_alg_ctx_t;

typedef struct state_fifo_node_st {
    int state;
    struct state_fifo_node_st *next;
} state_fifo_node_t;

typedef struct state_fifo_st {
    int nelm;
    state_fifo_node_t *head;
    state_fifo_node_t *tail;
} state_fifo_t;

static int state_fifo_init(state_fifo_t *fifo)
{
    fifo->nelm = 0;
    fifo->head = NULL;
    fifo->tail = NULL;
    return 0;
}

static int state_fifo_fini(state_fifo_t *fifo)
{
    state_fifo_node_t *cur;
    state_fifo_node_t *tmp;

    if (fifo == NULL) {
        return 0;
    }

    cur = fifo->head;
    while (cur) {
        tmp = cur->next;
        free(cur);
        cur = tmp;
    }

    fifo->head = fifo->tail = NULL;
    fifo->nelm = 0;
    return 0;
}

static int state_fifo_enqueue(state_fifo_t *fifo, int state)
{
    state_fifo_node_t *node;

    if (fifo == NULL) {
        return -EINVAL;
    }

    node = malloc(sizeof(state_fifo_node_t));
    if (node == NULL) {
        return -ENOMEM;
    }

    node->state = state;
    node->next = NULL;

    if (fifo->tail) {
        fifo->tail->next = node;
        fifo->tail = node;
    } else {
        fifo->head = node;
        fifo->tail = node;
    }

    fifo->nelm++;
    return 0;
}

static int state_fifo_dequeue(state_fifo_t *fifo, int *state)
{
    state_fifo_node_t *node;

    if (fifo && fifo->head) {
        node = fifo->head;
        fifo->head = node->next;
        if (fifo->head == NULL) {
            fifo->tail = NULL;
        }
        *state = node->state;
        free(node);
        fifo->nelm--;
        return 1;
    }

    return 0;
}

static int ac_alg_init(mpse_alg_ctx_t *ctx)
{
    ac_alg_ctx_t *priv;

    priv = mpse_malloc(sizeof(ac_alg_ctx_t));
    if (priv == NULL)
        return -ENOMEM;

    priv->n_states = 0;
    priv->n_patterns = 0;
    priv->goto_table = NULL;
    priv->failure_table = NULL;
    priv->output_table = NULL;
    priv->state.table = NULL;
    priv->pattern_table = NULL;

    ctx->data = priv;
    return 0;
}

static int ac_alg_fini(mpse_alg_ctx_t *ctx)
{
    int i;
    ac_alg_ctx_t *priv;

    priv = (ac_alg_ctx_t *)ctx->data;
    if (priv) {
        if (priv->goto_table) {
            mpse_free(priv->goto_table);
        }
        if (priv->failure_table) {
            mpse_free(priv->failure_table);
        }
        if (priv->output_table) {
            for (i=0; i<priv->n_states; i++) {
                mpse_free (priv->output_table[i].pids);
            }
            mpse_free(priv->output_table);
        }
        if (priv->state.table) {
            mpse_free(priv->state.table);
        }
        if (priv->pattern_table) {
            for (i=0; i<priv->n_patterns; i++) {
                if (priv->pattern_table[i].pattern) {
                    mpse_free(priv->pattern_table[i].pattern);
                }
            }
            mpse_free(priv->pattern_table);
        }
        mpse_free(priv);
    }

    return 0;
}

int build_ac_pattern_from_mpse_pattern(ac_alg_pattern_t *ac_pattern, mpse_pattern_t *mpse_pattern)
{
    ac_pattern->len = mpse_pattern->len;
    ac_pattern->offset0 = mpse_pattern->offset0;
    ac_pattern->offsetx = mpse_pattern->offsetx;
    ac_pattern->priority = mpse_pattern->priority;
    ac_pattern->tag = mpse_pattern->tag;

    if (mpse_pattern->nocase) {
        ac_pattern->pattern = NULL;
    } else {
        ac_pattern->pattern = mpse_malloc(mpse_pattern->len * sizeof(uint8_t));
        if (ac_pattern->pattern == NULL) {
            mpse_error("pattern malloc failed!\n");
            return -ENOMEM;
        }
        memcpy(ac_pattern->pattern, mpse_pattern->pattern, mpse_pattern->len);
    }

    return 0;
}

int ac_prepare_pattern_table(mpse_alg_ctx_t *ctx)
{
    int i;
    int ret;
    ac_alg_pattern_t *ac_pattern;
    mpse_pattern_t *mpse_pattern;
    ac_alg_ctx_t *priv = (ac_alg_ctx_t *)ctx->data;

    priv->n_patterns = ctx->n_patterns;
    priv->pattern_table = mpse_malloc(ctx->n_patterns * sizeof(ac_alg_pattern_t));
    if (priv->pattern_table == NULL) {
        mpse_error("pattern table malloc failed!\n");
        return -ENOMEM;
    }

    memset(priv->pattern_table, 0, ctx->n_patterns * sizeof(ac_alg_pattern_t));

    for (i = 0; i < ctx->n_patterns; i++) {
        mpse_pattern = ctx->patterns[i];
        ac_pattern = &priv->pattern_table[ctx->patterns[i]->pid];
        ret = build_ac_pattern_from_mpse_pattern(ac_pattern, mpse_pattern);
        if (ret < 0)
            return ret;
    }

    return 0;
}

static inline int ac_state_new(mpse_alg_ctx_t *ctx)
{
    int size = 0;
    int ascii_code = 0;
    ac_alg_ctx_t *priv = (ac_alg_ctx_t *)ctx->data;

    size = (priv->n_states + 1) * sizeof(int_array_t);
    priv->goto_table = mpse_realloc(priv->goto_table, size);
    if (priv->goto_table == NULL) {
        mpse_error("goto table re-malloc %d bytes failed!\n", size);
        return -ENOMEM;
    }

    for (ascii_code = 0; ascii_code < CHARSET_SIZE; ascii_code++) {
        priv->goto_table[priv->n_states][ascii_code] = AC_STATE_FAIL;
    }

    size = (priv->n_states + 1) * sizeof(ac_alg_output_t);
    priv->output_table = mpse_realloc(priv->output_table, size);
    if (priv->output_table == NULL) {
        mpse_error("output table re-malloc %d bytes failed!\n", size);
        return -ENOMEM;
    }

    memset(priv->output_table + priv->n_states, 0, sizeof(ac_alg_output_t));
    return priv->n_states++;
}

static inline int ac_state_set_output(mpse_alg_ctx_t *ctx, uint32_t state, mpse_pattern_t *pattern)
{
    int i = 0;
    ac_alg_output_pid_t *output_pid;
    ac_alg_ctx_t *priv = (ac_alg_ctx_t *)ctx->data;
    ac_alg_output_t *output = &priv->output_table[state];

    for (i = 0; i < output->n_pids; i++) {
        if (output->pids[i].pid == pattern->pid)
            return 0;
    }

    output->n_pids++;
    output->pids = mpse_realloc(output->pids, output->n_pids * sizeof(ac_alg_output_pid_t));
    if (output->pids == NULL) {
        mpse_error("output pid re-malloc failed!\n");
        return -ENOMEM;
    }

    output_pid = &output->pids[output->n_pids - 1];

    output_pid->pid = pattern->pid;
    output_pid->nocase = pattern->nocase;
    output_pid->offset0 = pattern->offset0;
    output_pid->offsetx = pattern->offsetx;
    output_pid->priority = pattern->priority;

    return 0;
}

static inline int ac_state_club_output(mpse_alg_ctx_t *ctx, uint32_t dst_state, uint32_t src_state)
{
    int i = 0;
    int j = 0;
    ac_alg_ctx_t *priv = (ac_alg_ctx_t *)ctx->data;

    ac_alg_output_pid_t *output_dst_pid;
    ac_alg_output_pid_t *output_src_pid;

    ac_alg_output_t *output_dst_state = &priv->output_table[dst_state];
    ac_alg_output_t *output_src_state = &priv->output_table[src_state];

    /** the output table is sorted by pid */
    for (i = 0; i < output_src_state->n_pids; i++) {
        for (j = 0; j < output_dst_state->n_pids; j++) {
            if (output_src_state->pids[i].pid == output_dst_state->pids[j].pid) {
                break;
            }
        }
        if (j == output_dst_state->n_pids) {
            output_dst_state->n_pids++;
            output_dst_state->pids = mpse_realloc(output_dst_state->pids, (output_dst_state->n_pids * sizeof(ac_alg_output_pid_t)));
            if (output_dst_state->pids == NULL) {
                mpse_error("club output pid re-malloc failed!\n");
                return -ENOMEM;
            }

            output_src_pid = &output_src_state->pids[i];
            output_dst_pid = &output_dst_state->pids[output_dst_state->n_pids - 1];

            output_dst_pid->pid = output_src_pid->pid;
            output_dst_pid->nocase = output_src_pid->nocase;
            output_dst_pid->offset0 = output_src_pid->offset0;
            output_dst_pid->offsetx = output_src_pid->offsetx;
            output_dst_pid->priority = output_src_pid->priority;
        }
    }

    return 0;
}

static inline int ac_load_pattern(mpse_alg_ctx_t *ctx, mpse_pattern_t *pattern)
{
    int i = 0;
    int p = 0;
    int state = 0;
    int newstate = 0;
    ac_alg_ctx_t *priv = (ac_alg_ctx_t *)ctx->data;

    state = 0;
    for (i = 0; i < pattern->len; i++) {
        if (priv->goto_table[state][pattern->lowercase_pattern[i]] != AC_STATE_FAIL) {
            state = priv->goto_table[state][pattern->lowercase_pattern[i]];
        } else {
            break;
        }
    }

    for (p = i; p < pattern->len; p++) {
        newstate = ac_state_new(ctx);
        if (newstate < 0)
            return -ENOMEM;
        priv->goto_table[state][pattern->lowercase_pattern[p]] = newstate;
        state = newstate;
    }

    return ac_state_set_output(ctx, state, pattern);
}

static inline int ac_create_goto_table(mpse_alg_ctx_t *ctx)
{
    int i = 0;
    int ret = 0;
    int ascii_code = 0;
    ac_alg_ctx_t *priv = (ac_alg_ctx_t *)ctx->data;

    for (i = 0; i < ctx->n_patterns; i++) {
        ret = ac_load_pattern(ctx, ctx->patterns[i]);
        if (ret < 0)
            return ret;
    }

    for (ascii_code = 0; ascii_code < CHARSET_SIZE; ascii_code++) {
        if (priv->goto_table[0][ascii_code] == AC_STATE_FAIL) {
            priv->goto_table[0][ascii_code] = 0;
        }
    }

    return 0;
}

static inline int ac_create_failure_table(mpse_alg_ctx_t *ctx)
{
    int ret = 0;
    int ascii_code = 0;
    int state = 0;
    int r_state = 0;
    ac_alg_ctx_t *priv = (ac_alg_ctx_t *)ctx->data;

    state_fifo_t fifo;

    mpse_debug("AC load %d patterns and total %d states.\n", priv->n_patterns, priv->n_states);
    priv->failure_table = mpse_malloc(priv->n_states * sizeof(int));
    if (priv->failure_table == NULL) {
        mpse_error("failure table malloc failed!\n");
        return -ENOMEM;
    }

    memset(priv->failure_table, 0, priv->n_states * sizeof(int));

    /* add the failure transitions for the 0th state, and add every non-fail
     * transition from the 0th state to the queue for further processing
     * of failure states
     */
    state_fifo_init(&fifo);
    for (ascii_code = 0; ascii_code < CHARSET_SIZE; ascii_code++) {
        int temp_state = priv->goto_table[0][ascii_code];
        if (temp_state != 0) {
            ret = state_fifo_enqueue(&fifo, temp_state);
            if (ret < 0) {
                mpse_error("enqueue failed!\n");
                state_fifo_fini(&fifo);
                return ret;
            }
            priv->failure_table[temp_state] = 0;
        }
    }

    while (state_fifo_dequeue(&fifo, &r_state)) {
        for (ascii_code = 0; ascii_code < CHARSET_SIZE; ascii_code++) {
            int temp_state = priv->goto_table[r_state][ascii_code];
            if (temp_state == AC_STATE_FAIL)
                continue;
            ret = state_fifo_enqueue(&fifo, temp_state);
            if (ret < 0) {
                mpse_error("enqueue failed!\n");
                state_fifo_fini(&fifo);
                return ret;
            }

            state = priv->failure_table[r_state];
            while(priv->goto_table[state][ascii_code] == AC_STATE_FAIL)
                state = priv->failure_table[state];
            priv->failure_table[temp_state] = priv->goto_table[state][ascii_code];
            ret = ac_state_club_output(ctx, temp_state, priv->failure_table[temp_state]);
            if (ret < 0) {
                state_fifo_fini(&fifo);
                return ret;
            }
        }
    }

    state_fifo_fini(&fifo);
    return 0;
}

static inline int ac_create_delta_table(mpse_alg_ctx_t *ctx)
{
    int ret;
    int r_state = 0;
    int ascii_code = 0;

    state_fifo_t fifo;
    ac_alg_ctx_t *priv = (ac_alg_ctx_t *)ctx->data;

    state_fifo_init(&fifo);
    if (priv->n_states < 0x10000) {
        priv->state.u16_table = mpse_malloc(priv->n_states * sizeof(uint16_array_t));
        if (priv->state.u16_table == NULL) {
            mpse_error("delta u16 table malloc failed!\n");
            state_fifo_fini(&fifo);
            return -ENOMEM;
        }

        memset(priv->state.u16_table, 0, priv->n_states * sizeof(uint16_array_t));

        for (ascii_code = 0; ascii_code < CHARSET_SIZE; ascii_code++) {
            int temp_state = priv->goto_table[0][ascii_code];
            priv->state.u16_table[0][ascii_code] = temp_state;
            if (temp_state != 0) {
                ret = state_fifo_enqueue(&fifo, temp_state);
                if (ret < 0) {
                    mpse_error("enqueue failed!\n");
                    state_fifo_fini(&fifo);
                    return ret;
                }
            }
        }

        while (state_fifo_dequeue(&fifo, &r_state)) {
            for (ascii_code = 0; ascii_code < CHARSET_SIZE; ascii_code++) {
                int temp_state = priv->goto_table[r_state][ascii_code];
                if (temp_state != AC_STATE_FAIL) {
                    ret = state_fifo_enqueue(&fifo, temp_state);
                    if (ret < 0) {
                        mpse_error("enqueue failed!\n");
                        state_fifo_fini(&fifo);
                        return ret;
                    }
                    priv->state.u16_table[r_state][ascii_code] = temp_state;
                } else {
                    priv->state.u16_table[r_state][ascii_code] =
                        priv->state.u16_table[priv->failure_table[r_state]][ascii_code];
                }
            }
        }
    } else {
        priv->state.u32_table = mpse_malloc(priv->n_states * sizeof(uint32_array_t));
        if (priv->state.u32_table == NULL) {
            mpse_error("delta u32 table malloc failed!\n");
            return -ENOMEM;
        }

        memset(priv->state.u32_table, 0, priv->n_states * sizeof(uint32_array_t));

        for (ascii_code = 0; ascii_code < CHARSET_SIZE; ascii_code++) {
            int temp_state = priv->goto_table[0][ascii_code];
            priv->state.u32_table[0][ascii_code] = temp_state;
            if (temp_state != 0) {
                ret = state_fifo_enqueue(&fifo, temp_state);
                if (ret < 0) {
                    mpse_error("enqueue failed!\n");
                    state_fifo_fini(&fifo);
                    return ret;
                }
            }
        }

        while (state_fifo_dequeue(&fifo, &r_state)) {
            for (ascii_code = 0; ascii_code < CHARSET_SIZE; ascii_code++) {
                int temp_state = priv->goto_table[r_state][ascii_code];
                if (temp_state != AC_STATE_FAIL) {
                    ret = state_fifo_enqueue(&fifo, temp_state);
                    if (ret < 0) {
                        mpse_error("enqueue failed!\n");
                        state_fifo_fini(&fifo);
                        return ret;
                    }
                    priv->state.u32_table[r_state][ascii_code] = temp_state;
                } else {
                    priv->state.u32_table[r_state][ascii_code] =
                        priv->state.u32_table[priv->failure_table[r_state]][ascii_code];
                }
            }
        }
    }

    return 0;
}

/**
 * if the current state has output, we made a mark by using the
 * 31th bit of the state.
 *
 * note: only the u32 state can be made mark.
 */
static inline void ac_state_set_output_flag(mpse_alg_ctx_t *ctx)
{
    int ascii_code = 0;
    int state = 0;
    int temp_state = 0;
    ac_alg_ctx_t *priv = (ac_alg_ctx_t *)ctx->data;

    if (priv->n_states < 0x10000)
        return;

    for (state = 0; state < priv->n_states; state++) {
        for (ascii_code = 0; ascii_code < CHARSET_SIZE; ascii_code++) {
            temp_state = priv->state.u32_table[state & 0x7FFFFFFF][ascii_code];
            if (priv->output_table[temp_state & 0x7FFFFFFF].n_pids != 0)
                priv->state.u32_table[state & 0x7FFFFFFF][ascii_code] |= 0x80000000;
        }
    }

    return;
}

static inline int ac_prepare_state_table(mpse_alg_ctx_t *ctx)
{
    int ret = 0;

    /* create the 0th state in the goto table and output_table */
    ret = ac_state_new(ctx);
    if (ret < 0)
        return ret;

    ret = ac_create_goto_table(ctx);
    if (ret < 0)
        return ret;

    ret = ac_create_failure_table(ctx);
    if (ret < 0)
        return ret;

    ret = ac_create_delta_table(ctx);
    if (ret < 0)
        return ret;

    ac_state_set_output_flag(ctx);

    return ret;
}

static void ac_prepare_recover_garbage(mpse_alg_ctx_t *ctx)
{
    ac_alg_ctx_t *priv = (ac_alg_ctx_t *)ctx->data;

    if (priv->goto_table) {
        mpse_free(priv->goto_table);
        priv->goto_table = NULL;
    }

    if (priv->failure_table) {
        mpse_free(priv->failure_table);
        priv->failure_table = NULL;
    }

    return;
}

static int ac_alg_prepare(mpse_alg_ctx_t *ctx)
{
    int ret;

    if (ctx->n_patterns == 0)
        return 0;

    ret = ac_prepare_pattern_table(ctx);
    if (ret < 0)
        return ret;

    ret = ac_prepare_state_table(ctx);
    if (ret < 0)
        return ret;

    ac_prepare_recover_garbage(ctx);

    return 0;
}

static int ac_alg_search(mpse_alg_ctx_t *ctx, uint8_t *text, uint16_t len, mpse_matchers_t *matchers, uint16_t flags)
{
    int i;
    uint32_t k = 0;
    uint16_t start = 0;
    uint32_t n_pids = 0;
    int n_matchers = 0;
    ac_alg_pattern_t *pattern = NULL;
    ac_alg_output_pid_t *pids = NULL;
    ac_alg_ctx_t *priv = (ac_alg_ctx_t *)ctx->data;

    if (ctx->n_patterns == 0)
        return 0;

    if (priv->n_states < 0x10000) {
        register int state = 0;
        for (i = 0; i < len; i++) {
            state = priv->state.u16_table[state][tolower(text[i])];
            if (priv->output_table[state].n_pids != 0) {
                n_pids = priv->output_table[state].n_pids;
                pids = priv->output_table[state].pids;
                for (k = 0; k < n_pids; k++) {
                    pattern = priv->pattern_table + pids[k].pid;
                    start = i - pattern->len + 1;

                    if (pids[k].offset0 && start != 0)
                        continue;
                    if (pids[k].offsetx && i != len - 1)
                        continue;

                    if (pids[k].nocase == 0) {
                        if (memcmp(pattern->pattern, text + start, pattern->len)) {
                            continue;
                        }
                    }

                    n_matchers = mpse_matchers_output(matchers, n_matchers, pids[k].priority, pids[k].pid, start, i, pattern->tag);
                }
            }
        }
    } else {
        register int state = 0;
        for (i = 0; i < len; i++) {
            state = priv->state.u32_table[state & 0x7FFFFFFF][tolower(text[i])];
            if (state & 0x80000000) {
                n_pids = priv->output_table[state & 0x7FFFFFFF].n_pids;
                pids = priv->output_table[state & 0x7FFFFFFF].pids;
                for (k = 0; k < n_pids; k++) {
                    pattern = priv->pattern_table + pids[k].pid;
                    start = i - pattern->len + 1;

                    if (pids[k].offset0 && start != 0)
                        continue;
                    if (pids[k].offsetx && i != len - 1)
                        continue;

                    if (pids[k].nocase == 0) {
                        if (memcmp(pattern->pattern, text + start, pattern->len)) {
                            continue;
                        }
                    }

                    n_matchers = mpse_matchers_output(matchers, n_matchers, pids[k].priority, pids[k].pid, start, i, pattern->tag);
                }
            }
        }
    }

    return n_matchers;
}

int ac_alg_memstat(mpse_alg_ctx_t *ctx)
{
    int i;
    int memstat = 0;
    ac_alg_ctx_t *priv;

    priv = (ac_alg_ctx_t *)ctx->data;
    if (priv) {
        memstat += sizeof(ac_alg_ctx_t);
        if (priv->output_table) {
            memstat += priv->n_states * sizeof(ac_alg_output_t);
            for (i=0; i<priv->n_states; i++) {
                memstat += priv->output_table[i].n_pids * sizeof(ac_alg_output_pid_t);
            }
        }

        if (priv->state.table) {
            if (priv->n_states < 0x10000) {
                memstat += priv->n_states * sizeof(uint16_array_t);
            } else {
                memstat += priv->n_states * sizeof(uint32_array_t);
            }
        }
    }

    return memstat;
}

mpse_alg_t ac = {
    .alg = MPSE_ALG_AC,
    .name = "AC",
    .alg_init = ac_alg_init,
    .alg_prepare = ac_alg_prepare,
    .alg_fini = ac_alg_fini,
    .alg_search = ac_alg_search,
    .alg_memstat = ac_alg_memstat,
};
