#include "liblist.h"

/**
 *single list
 */
static inline slist_node_t *slist_node_new(void *value)
{
    slist_node_t *node;

    node = malloc(sizeof(slist_node_t));
    if (node == NULL) {
        return NULL;
    }

    node->value = value;
    node->next = NULL;

    return node;
}

static int slist_node_cmp(void *cval, void *uval)
{
    return cval - uval;
}

int slist_init(slist_t * slist)
{
    slist->nelm = 0;
    slist->head = NULL;
    slist->tail = NULL;
    return 0;
}

void slist_fini(slist_t * slist, void (*data_fini) (void *ptr))
{
    slist_node_t *cur;
    slist_node_t *tmp;

    if (slist == NULL) {
        return;
    }

    cur = slist->head;
    while (cur) {
        tmp = cur->next;
        if (data_fini) {
            data_fini(cur->value);
        }
        free(cur);
        cur = tmp;
    }

    slist->head = slist->tail = NULL;
    slist->nelm = 0;
    return;
}

void slist_dump(FILE * fp, slist_t * slist, void (*data_dump) (FILE * fp,
        void *ptr, void *arg, int arg_len), void *arg, int arg_len)
{
    slist_node_t *cur;

    if (slist == NULL) {
        return;
    }

    cur = slist->head;
    while (cur) {
        if (data_dump) {
            data_dump(fp, cur->value, arg, arg_len);
        } else {
            fprintf(fp, "%p<", cur->value);
        }
        cur = cur->next;
    }
    if (!data_dump) {
        fprintf(fp, "\n");
    }
    return;
}

void slist_foreach(slist_t * slist, int (*handler) (void *value, void *arg,
        int arg_len), void *arg, int arg_len)
{
    slist_node_t *cur;

    if (slist == NULL || handler == NULL) {
        return;
    }

    cur = slist->head;
    while (cur) {
        if (handler(cur->value, arg, arg_len)) {
            break;
        }

        cur = cur->next;
    }

    return;
}

int slist_empty(slist_t * slist)
{
    if (slist == NULL) {
        return 1;
    }

    return (slist->head == NULL);
}

int slist_add(slist_t * slist, void *value)
{
    slist_node_t *cur;
    slist_node_t *node;

    if (slist == NULL) {
        return -1;
    }

    node = slist_node_new(value);
    if (node == NULL) {
        return -1;
    }

    if (slist->head) {
        cur = slist->head;
        slist->head = node;
        node->next = cur;
    } else {
        slist->head = node;
        slist->tail = node;
    }

    slist->nelm++;
    return 0;
}

int slist_add_tail(slist_t * slist, void *value)
{
    slist_node_t *node;

    if (slist == NULL) {
        return -1;
    }

    node = slist_node_new(value);
    if (node == NULL) {
        return -1;
    }

    if (slist->tail) {
        slist->tail->next = node;
        slist->tail = node;
    } else {
        slist->head = node;
        slist->tail = node;
    }

    slist->nelm++;
    return 0;
}

int slist_add_exclusive(slist_t * slist, void *value,
    int (*cmp) (void *cval, void *uval))
{
    slist_node_t *cur;
    slist_node_t *node;

    if (slist == NULL) {
        return -1;
    }

    cur = slist->head;
    while (cur) {
        if (cmp) {
            if (!cmp(cur->value, value)) {
                return 1;
            }
        } else {
            if (cur->value == value) {
                return 1;
            }
        }
        cur = cur->next;
    }

    node = slist_node_new(value);
    if (node == NULL) {
        return -1;
    }

    if (slist->head) {
        cur = slist->head;
        slist->head = node;
        node->next = cur;
    } else {
        slist->head = node;
        slist->tail = node;
    }

    slist->nelm++;
    return 0;
}

int slist_add_tail_exclusive(slist_t * slist, void *value,
    int (*cmp) (void *cval, void *uval))
{
    slist_node_t *cur;
    slist_node_t *node;

    if (slist == NULL) {
        return -1;
    }

    cur = slist->head;
    while (cur) {
        if (cmp) {
            if (!cmp(cur->value, value)) {
                return 1;
            }
        } else {
            if (cur->value == value) {
                return 1;
            }
        }
        cur = cur->next;
    }

    node = slist_node_new(value);
    if (node == NULL) {
        return -1;
    }

    if (slist->tail) {
        slist->tail->next = node;
        slist->tail = node;
    } else {
        slist->head = node;
        slist->tail = node;
    }

    slist->nelm++;
    return 0;
}

int slist_add_sort(slist_t * slist, void *value,
    int (*cmp) (void *cval, void *uval))
{
    slist_node_t *cur;
    slist_node_t *pos;
    slist_node_t *tmp;
    slist_node_t *node;

    if (slist == NULL) {
        return -1;
    }

    node = slist_node_new(value);
    if (node == NULL) {
        return -1;
    }

    if (cmp == NULL) {
        cmp = slist_node_cmp;
    }

    if (slist->head) {
        cur = slist->head;
        pos = slist->tail;
        if (cur != pos) {       // node num > 1
            if (cmp(cur->value, node->value) > 0) {
                // switch head!
                tmp = slist->head;
                slist->head = node;
                node->next = tmp;
            } else {
                if (cmp(pos->value, node->value) > 0) {
                    for (; cur && cmp(cur->value, node->value) <= 0;
                        pos = cur, cur = cur->next);

                    tmp = pos->next;
                    pos->next = node;
                    node->next = tmp;
                    if (pos == slist->tail) {
                        // find the position at tail!
                        slist->tail = node;
                    }
                } else {
                    // just insert at tail!
                    pos->next = node;
                    slist->tail = node;
                }
            }
        } else {                // only one node!
            if (cmp(pos->value, node->value) > 0) {
                tmp = slist->head;
                slist->head = node;
                node->next = tmp;
            } else {
                pos->next = node;
                slist->tail = node;
            }
        }
    } else {
        pos = NULL;
        slist->head = node;
        slist->tail = node;
    }

    slist->nelm++;
    return 0;
}

int slist_add_sort_exclusive(slist_t * slist, void *value,
    int (*cmp) (void *cval, void *uval))
{
    int res;
    slist_node_t *cur;
    slist_node_t *pos;
    slist_node_t *tmp;
    slist_node_t *node;

    if (slist == NULL) {
        return -1;
    }

    node = slist_node_new(value);
    if (node == NULL) {
        return -1;
    }

    if (cmp == NULL) {
        cmp = slist_node_cmp;
    }

    if (slist->head) {
        cur = slist->head;
        pos = slist->tail;
        if (cur != pos) {       // node num > 1
            res = cmp(cur->value, node->value);
            if (res == 0) {
                free(node);
                return 1;
            }

            if (res > 0) {
                // switch head!
                tmp = slist->head;
                slist->head = node;
                node->next = tmp;
            } else {
                res = cmp(pos->value, node->value);
                if (res == 0) {
                    free(node);
                    return 1;
                }

                if (res > 0) {
                    for (; cur; pos = cur, cur = cur->next) {
                        res = cmp(cur->value, node->value);
                        if (res == 0) {
                            free(node);
                            return 1;
                        }
                        if (res > 0)
                            break;
                    }

                    tmp = pos->next;
                    pos->next = node;
                    node->next = tmp;
                    if (pos == slist->tail) {
                        // find the position at tail!
                        slist->tail = node;
                    }
                } else {
                    // just insert at tail!
                    pos->next = node;
                    slist->tail = node;
                }
            }
        } else {                // only one node!
            res = cmp(pos->value, node->value);
            if (res == 0) {
                free(node);
                return 1;
            }

            if (res > 0) {
                tmp = slist->head;
                slist->head = node;
                node->next = tmp;
            } else {
                pos->next = node;
                slist->tail = node;
            }
        }
    } else {
        pos = NULL;
        slist->head = node;
        slist->tail = node;
    }

    slist->nelm++;
    return 0;
}

int slist_equal(slist_t * sort_l1, slist_t * sort_l2,
    int (*cmp) (void *cval, void *uval))
{
    slist_node_t *cur1, *cur2;

    if (sort_l1 == NULL && sort_l2 == NULL) {
        return 1;
    }

    if (sort_l1 == NULL || sort_l2 == NULL) {
        return 0;
    }

    if (sort_l1->nelm != sort_l2->nelm) {
        return 0;
    }

    for (cur1 = sort_l1->head, cur2 = sort_l2->head;
        cur1 && cur2; cur1 = cur1->next, cur2 = cur2->next) {
        if (cmp) {
            if (cmp(cur1->value, cur2->value)) {
                return 0;
            }
        } else {
            if (cur1->value != cur2->value) {
                return 0;
            }
        }
    }

    return 1;
}

int slist_subset(slist_t * set, slist_t * subset,
        int (*cmp) (void *cval, void *uval))
{
    int inset = 0;
    slist_node_t *cur1, *cur2;

    if (subset == NULL || slist_empty(subset)) {
        return 1;
    }

    if (set == NULL)
        return 0;

    if (cmp == NULL) {
        cmp = slist_node_cmp;
    }

    for (cur1 = subset->head; cur1; cur1 = cur1->next) {
        inset = 0;
        for (cur2 = set->head; cur2; cur2 = cur2->next) {
            if (!cmp(cur1->value, cur2->value)) {
                inset = 1;
                break;
            }
        }
        if (!inset) {
            return 0;
        }
    }

    return 1;
}


int slist_del(slist_t * slist, void **value)
{
    slist_node_t *node;

    if (slist && slist->head) {
        node = slist->head;
        slist->head = node->next;
        if (slist->head == NULL) {
            slist->tail = NULL;
        }
        *value = node->value;
        free(node);
        slist->nelm--;
        return 1;
    }

    return 0;
}

int slist_peek(slist_t * slist, void **value)
{
    slist_node_t *node;

    if (slist && slist->head) {
        node = slist->head;
        *value = node->value;
        return 1;
    }

    return 0;
}

int slist_copy(slist_t * dst, slist_t * src)
{
    slist_node_t *cur;
    slist_node_t *node;

    if (dst == NULL || src == NULL) {
        return -1;
    }

    dst->nelm = 0;
    dst->head = dst->tail = NULL;

    cur = src->head;
    while (cur) {
        node = slist_node_new(cur->value);
        if (node == NULL) {
            return -1;
        }

        if (dst->tail) {
            dst->tail->next = node;
            dst->tail = node;
        } else {
            dst->head = node;
            dst->tail = node;
        }

        dst->nelm++;

        cur = cur->next;
    }

    return 0;
}

int slist_append(slist_t * dst, slist_t * src)
{
    slist_node_t *cur;
    slist_node_t *node;

    if (dst == NULL || src == NULL) {
        return -1;
    }

    cur = src->head;
    while (cur) {
        node = slist_node_new(cur->value);
        if (node == NULL) {
            return -1;
        }

        if (dst->tail) {
            dst->tail->next = node;
            dst->tail = node;
        } else {
            dst->head = node;
            dst->tail = node;
        }

        dst->nelm++;

        cur = cur->next;
    }

    return 0;
}

int slist_array(slist_t *slist, void ***pblockarray)
{
    int i = 0;
    void **blockarray;
    slist_node_t *node;

    if (slist == NULL)
        return -1;

    blockarray = malloc(slist->nelm * sizeof(void *));
    if (blockarray == NULL)
        return -1;

    node = slist->head;
    while (node) {
        blockarray[i++] = node->value;
        node = node->next;
    }

    *pblockarray = blockarray;
    return slist->nelm;
}

int slist_index(slist_t * slist, void *value,
    int (*cmp) (void *cval, void *uval))
{
    int idx;
    slist_node_t *cur;

    if (slist == NULL) {
        return -1;
    }

    if (cmp == NULL) {
        cmp = slist_node_cmp;
    }

    idx = 0;
    cur = slist->head;
    while (cur) {
        if (!cmp(cur->value, value)) {
            return idx;
        }
        cur = cur->next;
        idx++;
    }

    return -1;
}

void *slist_search(slist_t * slist, void *value,
    int (*cmp) (void *cval, void *uval))
{
    slist_node_t *cur;

    if (slist == NULL) {
        return NULL;
    }

    if (cmp == NULL) {
        cmp = slist_node_cmp;
    }

    cur = slist->head;
    while (cur) {
        if (!cmp(cur->value, value)) {
            return cur->value;
        }
        cur = cur->next;
    }

    return NULL;
}

int slist_searchall(slist_t * slist, void *value,
    int (*cmp) (void *cval, void *uval),
    int (*handler) (void *value, void *matched))
{
    int cnt = 0;
    slist_node_t *cur;

    if (slist == NULL) {
        return 0;
    }

    if (cmp == NULL) {
        cmp = slist_node_cmp;
    }

    cur = slist->head;
    while (cur) {
        if (!cmp(cur->value, value)) {
            if (handler) {
                handler(value, cur->value);
            }
            cnt++;
        }
        cur = cur->next;
    }

    return cnt;
}

void *slist_delete(slist_t * slist, void *value,
    int (*cmp) (void *cval, void *uval))
{
    slist_node_t *cur, *prev;

    if (slist == NULL) {
        return NULL;
    }

    if (cmp == NULL) {
        cmp = slist_node_cmp;
    }

    prev = NULL;
    cur = slist->head;
    while (cur) {
        if (!cmp(cur->value, value)) {
            if (prev) {
                prev->next = cur->next;
            } else {
                slist->head = cur->next;
            }
            value = cur->value;
            free(cur);
            slist->nelm--;
            return value;
        }
        prev = cur;
        cur = cur->next;
    }

    return NULL;
}

int slist_max(slist_t * slist, int (*value) (void *p))
{
    int v, max = 0;
    slist_node_t *cur;

    if (slist == NULL) {
        return 0;
    }

    cur = slist->head;
    while (cur) {
        v = value(cur->value);
        if (v > max) {
            max = v;
        }
        cur = cur->next;
    }

    return max;
}

int slist_min(slist_t * slist, int (*value) (void *p))
{
    unsigned int v, min = -1;
    slist_node_t *cur;

    if (slist == NULL) {
        return 0;
    }

    cur = slist->head;
    while (cur) {
        v = value(cur->value);
        if (v < min) {
            min = v;
        }
        cur = cur->next;
    }

    return min;
}

/**
 *dlist
 */
static inline dlist_node_t *dlist_node_new(void *value)
{
    dlist_node_t *node;

    node = malloc(sizeof(dlist_node_t));
    if (node == NULL) {
        return NULL;
    }

    node->value = value;
    node->next = NULL;
    node->prev = NULL;

    return node;
}

int dlist_init(dlist_t * dlist)
{
    dlist->nelm = 0;
    dlist->head.next = &dlist->head;
    dlist->head.prev = &dlist->head;
    return 0;
}

void dlist_fini(dlist_t * dlist, void (*data_fini) (void *ptr))
{
    dlist_node_t *cur;
    dlist_node_t *tmp;

    if (dlist == NULL) {
        return;
    }

    for (cur = dlist->head.next, tmp = cur->next;
        cur != &dlist->head; cur = tmp, tmp = cur->next) {
        if (data_fini) {
            data_fini(cur->value);
        }
        free(cur);
    }

    dlist->nelm = 0;
    dlist->head.next = &dlist->head;
    dlist->head.prev = &dlist->head;
    return;
}

int dlist_add(dlist_t * dlist, void *value)
{
    dlist_node_t *next;
    dlist_node_t *new_node;

    if (dlist == NULL) {
        return -1;
    }

    new_node = dlist_node_new(value);
    if (new_node == NULL) {
        return -1;
    }

    next = dlist->head.next;
    next->prev = new_node;
    new_node->next = next;
    new_node->prev = &dlist->head;
    dlist->head.next = new_node;

    dlist->nelm++;
    return 0;
}

int dlist_add_tail(dlist_t * dlist, void *value)
{
    dlist_node_t *prev;
    dlist_node_t *new_node;

    if (dlist == NULL) {
        return -1;
    }

    new_node = dlist_node_new(value);
    if (new_node == NULL) {
        return -1;
    }

    prev = dlist->head.prev;
    prev->next = new_node;
    new_node->prev = prev;
    new_node->next = &dlist->head;
    dlist->head.prev = new_node;

    dlist->nelm++;
    return 0;
}

int dlist_empty(dlist_t * dlist)
{
    if (dlist == NULL) {
        return 1;
    }

    return (dlist->head.next == &dlist->head);
}

int dlist_del(dlist_t * dlist, void **value)
{
    dlist_node_t *node;

    if (dlist && !dlist_empty(dlist)) {
        node = dlist->head.next;

        node->next->prev = node->prev;
        node->prev->next = node->next;
        *value = node->value;

        free(node);
        dlist->nelm--;
        return 1;
    }

    return 0;
}

int dlist_del_tail(dlist_t * dlist, void **value)
{
    dlist_node_t *node;

    if (dlist && !dlist_empty(dlist)) {
        node = dlist->head.prev;

        node->next->prev = node->prev;
        node->prev->next = node->next;
        *value = node->value;

        free(node);
        dlist->nelm--;
        return 1;
    }

    return 0;
}

int dlist_peek(dlist_t * dlist, void **value)
{
    dlist_node_t *node;

    if (dlist && !dlist_empty(dlist)) {
        node = dlist->head.next;
        *value = node->value;
        return 1;
    }

    return 0;
}

int dlist_peek_tail(dlist_t * dlist, void **value)
{
    dlist_node_t *node;

    if (dlist && !dlist_empty(dlist)) {
        node = dlist->head.prev;
        *value = node->value;
        return 1;
    }

    return 0;
}

void dlist_dump(FILE * fp, dlist_t * dlist, void (*data_dump) (FILE * fp,
        void *ptr, void *arg, int arg_len), void *arg, int arg_len)
{
    dlist_node_t *cur;

    if (dlist == NULL) {
        return;
    }

    for (cur = dlist->head.next; cur != &dlist->head; cur = cur->next) {
        if (data_dump) {
            data_dump(fp, cur->value, arg, arg_len);
        } else
            fprintf(fp, "%p<", cur->value);
    }
    if (!data_dump) {
        fprintf(fp, "\n");
    }
    return;
}

void dlist_foreach(dlist_t * dlist, int (*handler) (void *ptr, void *arg,
        int arg_len), void *arg, int arg_len)
{
    dlist_node_t *cur;

    if (dlist == NULL || handler == NULL) {
        return;
    }

    for (cur = dlist->head.next; cur != &dlist->head; cur = cur->next) {
        if (handler(cur->value, arg, arg_len)) {
            break;
        }
    }

    return;
}

int dlist_append(dlist_t * dst, dlist_t * src)
{
    int ret;
    dlist_node_t *cur;

    if (dst == NULL || src == NULL) {
        return -1;
    }

    for (cur = src->head.next; cur != &src->head; cur = cur->next) {
        ret = dlist_add_tail(dst, cur->value);
        if (ret < 0) {
            return -1;
        }
    }

    return 0;
}
