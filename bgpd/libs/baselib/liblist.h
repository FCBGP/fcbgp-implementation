#ifndef LIBLIST_H
#define LIBLIST_H

#include "libtypes.h"

struct list_head {
    struct list_head *next;
    struct list_head *prev;
};

static inline void INIT_LIST_HEAD(struct list_head *list)
{
    list->next = list;
    list->prev = list;
}

/**
 * @fn __list_add
 * @brief Insert a new entry between two known consecutive entries.
 *
 * This is only for internal list manipulation where we know
 * the prev/next entries already!
 */
static inline void __list_add(struct list_head * node, struct list_head * prev,
                                 struct list_head * next)
{
    next->prev = node;
    node->next = next;
    node->prev = prev;
    prev->next = node;
}

/**
 * @fn list_add
 * @brief add a new entry
 * @param new - new entry to be added
 * @param head - list head to add it after
 *
 * Insert a new entry after the specified head.
 * This is good for implementing stacks.
 */
static inline void my_list_add(struct list_head * node, struct list_head * head)
{
    __list_add(node, head, head->next);
}

/**
 * @fn list_add_tail
 * @brief add a new entry
 * @param new - new entry to be added
 * @param head - list head to add it before
 *
 * Insert a new entry before the specified head.
 * This is useful for implementing queues.
 */
static inline void list_add_tail(struct list_head * node, struct list_head * head)
{
    __list_add(node, head->prev, head);
}

/**
 * @fn __list_del
 * @brief Delete a list entry by making the prev/next entries
 * point to each other.
 *
 * This is only for internal list manipulation where we know
 * the prev/next entries already!
 */
static inline void __list_del(struct list_head * prev, struct list_head * next)
{
    next->prev = prev;
    prev->next = next;
}

/**
 * @fn list_del
 * @brief deletes entry from list.
 * @param entry - the element to delete from the list.
 * Note - list_empty on entry does not return true after this, the entry is
 * in an undefined state.
 */
static inline void list_del(struct list_head * entry)
{
    __list_del(entry->prev, entry->next);
}

/**
 * @fn list_move
 * @brief delete from one list and add as another's head
 * @param list - the entry to move
 * @param head - the head that will precede our entry
 */
static inline void list_move(struct list_head *list, struct list_head *head)
{
    __list_del(list->prev, list->next);
    my_list_add(list, head);
}

/**
 * @fn list_move_tail
 * @brief delete from one list and add as another's tail
 * @param list - the entry to move
 * @param head - the head that will follow our entry
 */
static inline void list_move_tail(struct list_head *list,
        struct list_head *head)
{
    __list_del(list->prev, list->next);
    list_add_tail(list, head);
}

/**
 * @fn list_is_first
 * @brief tests whether @list is the first entry in list @head
 * @param list - the entry to test
 * @param head - the head of the list
 */
static inline int list_is_first(const struct list_head *list,
        const struct list_head *head)
{
    return list->prev == head;
}

/**
 * @fn list_is_last
 * @brief tests whether @list is the last entry in list @head
 * @param list - the entry to test
 * @param head - the head of the list
 */
static inline int list_is_last(const struct list_head *list,
        const struct list_head *head)
{
    return list->next == head;
}

/**
 * @fn list_empty
 * @brief tests whether a list is empty
 * @param head - the list to test.
 */
static inline int list_empty(struct list_head * head)
{
    return (head->next == head);
}

/**
 * @fn list_splice
 * @brief join two lists
 * @param list - the new list to add.
 * @param head - the place to add it in the first list.
 */
static inline void list_splice(struct list_head * list, struct list_head * head)
{
    struct list_head *first = list->next;

    if (first != list) {
        struct list_head *last = list->prev;
        struct list_head *at = head->next;

        first->prev = head;
        head->next = first;

        last->next = at;
        at->prev = last;
    }
}

/**
 * @def list_entry
 * @brief get the struct for this entry
 * @param ptr - the &struct list_head pointer.
 * @param type - the type of the struct this is embedded in.
 * @param member - the name of the list_struct within the struct.
 */
#define list_entry(ptr, type, member) container_of(ptr, type, member)

/**
 * @def list_first_entry
 * @brief get the first element from a list
 * @param ptr - the list head to take the element from.
 * @param type - the type of the struct this is embedded in.
 * @param member - the name of the list_struct within the struct.
 *
 * Note, that list is expected to be not empty.
 */
#define list_first_entry(ptr, type, member) list_entry((ptr)->next, type, member)

/**
 * @def list_last_entry
 * @brief get the last element from a list
 * @param ptr - the list head to take the element from.
 * @param type - the type of the struct this is embedded in.
 * @param member - the name of the list_struct within the struct.
 *
 * Note, that list is expected to be not empty.
 */
#define list_last_entry(ptr, type, member) list_entry((ptr)->prev, type, member)

/**
 * @def list_for_each
 * @brief iterate over a list
 * @param pos - the &struct list_head to use as a loop counter.
 * @param head - the head for your list.
 */
#define list_for_each(pos, head) \
    for (pos = (head)->next; pos != (head); pos = pos->next)

/**
 * @def list_for_each_safe
 * @brief iterate over a list safe against removal of list entry
 * @param pos - the &struct list_head to use as a loop counter.
 * @param n - another &struct list_head to use as temporary storage
 * @param head - the head for your list.
 */
#define list_for_each_safe(pos, n, head) \
    for (pos = (head)->next, n = pos->next; pos != (head); pos = n, n = pos->next)

/**
 * @def list_for_each_prev
 * @brief iterate over a list backwards
 * @param pos - the &struct list_head to use as a loop counter.
 * @param head - the head for your list.
 */
#define list_for_each_prev(pos, head) \
    for (pos = (head)->prev; pos != (head); pos = pos->prev)

/**
 * @def list_for_each_entry
 * @brief iterate over list of given type
 * @param pos - the type * to use as a loop counter.
 * @param head - the head for your list.
 * @param member - the name of the list_struct within the struct.
 */
#define list_for_each_entry(pos, head, member) \
    for (pos = list_entry((head)->next, typeof(*pos), member); \
         &pos->member != (head); \
         pos = list_entry(pos->member.next, typeof(*pos), member))

/**
 * @def list_for_each_entry_reverse
 * @brief iterate backwards over list of given type.
 * @param pos - the type * to use as a loop counter.
 * @param head - the head for your list.
 * @param member - the name of the list_struct within the struct.
 */
#define list_for_each_entry_reverse(pos, head, member) \
    for (pos = list_entry((head)->prev, typeof(*pos), member); \
         &pos->member != (head); \
         pos = list_entry(pos->member.prev, typeof(*pos), member))

/**
 * @def list_for_each_entry_safe
 * @brief iterate over list of given type safe against removal of list entry
 * @param pos - the type * to use as a loop counter.
 * @param n - another type * to use as temporary storage
 * @param head - the head for your list.
 * @param member - the name of the list_struct within the struct.
 */
#define list_for_each_entry_safe(pos, n, head, member) \
    for (pos = list_entry((head)->next, typeof(*pos), member), \
        n = list_entry(pos->member.next, typeof(*pos), member); \
         &pos->member != (head); \
         pos = n, n = list_entry(n->member.next, typeof(*n), member))

/*
 * Double linked lists with a single pointer list head.
 * Mostly useful for hash tables where the two pointer list head is
 * too wasteful.
 * You lose the ability to access the tail in O(1).
 */

struct hlist_head {
    struct hlist_node *first;
};

struct hlist_node {
    struct hlist_node *next, **pprev;
};

#define INIT_HLIST_HEAD(ptr) ((ptr)->first = NULL)

static inline void INIT_HLIST_NODE(struct hlist_node *h)
{
    h->next = NULL;
    h->pprev = NULL;
}

static inline int hlist_unhashed(const struct hlist_node *h)
{
    return !h->pprev;
}

static inline int hlist_empty(const struct hlist_head *h)
{
    return !h->first;
}

static inline void __hlist_del(struct hlist_node *n)
{
    struct hlist_node *next = n->next;
    struct hlist_node **pprev = n->pprev;
    *pprev = next;
    if (next)
        next->pprev = pprev;
}

static inline void hlist_del(struct hlist_node *n)
{
    __hlist_del(n);
    n->next = NULL;
    n->pprev = NULL;
}

static inline void hlist_del_init(struct hlist_node *n)
{
    if (!hlist_unhashed(n)) {
        __hlist_del(n);
        INIT_HLIST_NODE(n);
    }
}

static inline void hlist_add_head(struct hlist_node *n, struct hlist_head *h)
{
    struct hlist_node *first = h->first;
    n->next = first;
    if (first)
        first->pprev = &n->next;
    h->first = n;
    n->pprev = &h->first;
}

/* next must be != NULL */
static inline void hlist_add_before(struct hlist_node *n,
                    struct hlist_node *next)
{
    n->pprev = next->pprev;
    n->next = next;
    next->pprev = &n->next;
    *(n->pprev) = n;
}

static inline void hlist_add_after(struct hlist_node *n,
                    struct hlist_node *next)
{
    next->next = n->next;
    n->next = next;
    next->pprev = &n->next;

    if(next->next)
        next->next->pprev  = &next->next;
}

/*
 * Move a list from one list head to another. Fixup the pprev
 * reference of the first entry if it exists.
 */
static inline void hlist_move_list(struct hlist_head *old,
                   struct hlist_head *new)
{
    new->first = old->first;
    if (new->first)
        new->first->pprev = &new->first;
    old->first = NULL;
}

/**
 * hlist_entry    - iterate over list of given type
 * @param tpos - the type * to use as a loop cursor.
 * @param pos - the &struct hlist_node to use as a loop cursor.
 * @param head - the head for your list.
 * @param member - the name of the hlist_node within the struct.
 */
#define hlist_entry(ptr, type, member) container_of(ptr, type, member)

#define hlist_for_each(pos, head) \
    for (pos = (head)->first; pos; pos = pos->next)

#define hlist_for_each_safe(pos, n, head) \
    for (pos = (head)->first; pos && ({ n = pos->next; 1; }); \
         pos = n)

/**
 * @fn hlist_for_each_entry
 * @brief iterate over list of given type
 * @param tpos - the type * to use as a loop cursor.
 * @param pos - the &struct hlist_node to use as a loop cursor.
 * @param head - the head for your list.
 * @param member - the name of the hlist_node within the struct.
 */
#define hlist_for_each_entry(tpos, pos, head, member)             \
    for (pos = (head)->first;                     \
         pos &&          \
        ({ tpos = hlist_entry(pos, typeof(*tpos), member); 1;}); \
         pos = pos->next)

/**
 * @fn hlist_for_each_entry_continue
 * @brief iterate over a hlist continuing after current point
 * @param tpos - the type * to use as a loop cursor.
 * @param pos - the &struct hlist_node to use as a loop cursor.
 * @param member - the name of the hlist_node within the struct.
 */
#define hlist_for_each_entry_continue(tpos, pos, member)         \
    for (pos = (pos)->next;                      \
         pos &&          \
        ({ tpos = hlist_entry(pos, typeof(*tpos), member); 1;}); \
         pos = pos->next)

/**
 * @fn hlist_for_each_entry_from
 * @brief iterate over a hlist continuing from current point
 * @param tpos - the type * to use as a loop cursor.
 * @param pos - the &struct hlist_node to use as a loop cursor.
 * @param member - the name of the hlist_node within the struct.
 */
#define hlist_for_each_entry_from(tpos, pos, member)             \
    for (; pos && \
        ({ tpos = hlist_entry(pos, typeof(*tpos), member); 1;}); \
         pos = pos->next)

/**
 * @fn hlist_for_each_entry_safe
 * @brief iterate over list of given type safe against removal of list entry
 * @param tpos - the type * to use as a loop cursor.
 * @param pos - the &struct hlist_node to use as a loop cursor.
 * @param n - another &struct hlist_node to use as temporary storage
 * @param head - the head for your list.
 * @param member - the name of the hlist_node within the struct.
 */
#define hlist_for_each_entry_safe(tpos, pos, n, head, member)          \
    for (pos = (head)->first;                     \
         pos && ({ n = pos->next; 1; }) &&                 \
        ({ tpos = hlist_entry(pos, typeof(*tpos), member); 1;}); \
         pos = n)


/**
 *single list
 *@note there is no slist_del_tail and slist_peek_tail here!
 */
typedef struct slist_node_st {
    void *value;
    struct slist_node_st *next;
} slist_node_t;

typedef struct slist_st {
    int nelm;
    slist_node_t *head;
    slist_node_t *tail;
} slist_t;

/**
 *single list fifo
 */
typedef slist_t fifo_t;
#define fifo_init(fifo) slist_init(fifo)
#define fifo_fini(fifo, data_fini) slist_fini(fifo, data_fini)
#define fifo_dump(fp, fifo, data_dump, adjust) slist_dump(fp, fifo, data_dump, adjust)
#define fifo_empty(fifo) slist_empty(fifo)
#define fifo_enqueue(fifo, value) slist_add_tail(fifo, value)
#define fifo_enqueue_exclusive(fifo, value, cmp) slist_add_tail_exclusive(fifo, value, cmp)
#define fifo_dequeue(fifo, ptr) slist_del(fifo, ptr)
#define fifo_peek(fifo, ptr) slist_peek(fifo, ptr)
#define fifo_copy(dst, src) slist_copy(dst, src)
#define fifo_append(dst, src) slist_append(dst, src)

/**
 *single list filo
 */
typedef slist_t filo_t;
#define filo_init(filo) slist_init(filo)
#define filo_fini(filo, data_fini) slist_fini(filo, data_fini)
#define filo_dump(fp, filo, data_dump, adjust) slist_dump(fp, filo, data_dump, adjust)
#define filo_empty(filo) slist_empty(filo)
#define filo_enqueue(filo, value) slist_add(filo, value)
#define filo_enqueue_exclusive(filo, value, cmp) slist_add_exclusive(filo, value, cmp)
#define filo_dequeue(filo, ptr) slist_del(filo, ptr)
#define filo_peek(filo, ptr) slist_peek(filo, ptr)
#define filo_copy(dst, src) slist_copy(dst, src)
#define filo_append(dst, src) slist_append(dst, src)

/**
 *double list
 */
typedef struct dlist_node_st {
    void *value;
    struct dlist_node_st *prev;
    struct dlist_node_st *next;
} dlist_node_t;

typedef struct dlist_st {
    int nelm;
    dlist_node_t head;
} dlist_t;

/* liblist.c */
int slist_init(slist_t *slist);
void slist_fini(slist_t *slist, void (*data_fini)(void *ptr));
void slist_dump(FILE *fp, slist_t *slist, void (*data_dump)(FILE *fp, void *ptr, void *arg, int arg_len), void *arg, int arg_len);
void slist_foreach(slist_t *slist, int (*handler)(void *value, void *arg, int arg_len), void *arg, int arg_len);
int slist_empty(slist_t *slist);
int slist_add(slist_t *slist, void *value);
int slist_add_tail(slist_t *slist, void *value);
int slist_add_exclusive(slist_t *slist, void *value, int (*cmp)(void *cval, void *uval));
int slist_add_tail_exclusive(slist_t *slist, void *value, int (*cmp)(void *cval, void *uval));
int slist_add_sort(slist_t *slist, void *value, int (*cmp)(void *cval, void *uval));
int slist_add_sort_exclusive(slist_t * slist, void *value, int (*cmp) (void *cval, void *uval));
int slist_equal(slist_t *sort_l1, slist_t *sort_l2, int (*cmp)(void *cval, void *uval));
int slist_subset(slist_t * set, slist_t * subset, int (*cmp) (void *cval, void *uval));
int slist_del(slist_t *slist, void **value);
int slist_peek(slist_t *slist, void **value);
int slist_copy(slist_t *dst, slist_t *src);
int slist_append(slist_t *dst, slist_t *src);
int slist_array(slist_t *slist, void ***pblockarray);
int slist_index(slist_t *slist, void *value, int (*cmp)(void *cval, void *uval));
void *slist_search(slist_t *slist, void *value, int (*cmp)(void *cval, void *uval));
void *slist_delete(slist_t * slist, void *value, int (*cmp) (void *cval, void *uval));
int slist_searchall(slist_t *slist, void *value, int (*cmp)(void *cval, void *uval), int (*handler)(void *value, void *matched));
int slist_max(slist_t *slist, int (*value)(void *p));
int slist_min(slist_t *slist, int (*value)(void *p));

int dlist_init(dlist_t *dlist);
void dlist_fini(dlist_t *dlist, void (*data_fini)(void *ptr));
int dlist_add(dlist_t *dlist, void *value);
int dlist_add_tail(dlist_t *dlist, void *value);
int dlist_empty(dlist_t *dlist);
int dlist_del(dlist_t *dlist, void **value);
int dlist_del_tail(dlist_t *dlist, void **value);
int dlist_peek(dlist_t *dlist, void **value);
int dlist_peek_tail(dlist_t *dlist, void **value);
void dlist_dump(FILE *fp, dlist_t *dlist, void (*data_dump)(FILE *fp, void *ptr, void *arg, int arg_len), void *arg, int arg_len);
void dlist_foreach(dlist_t *dlist, int (*handler)(void *ptr, void *arg, int arg_len), void *arg, int arg_len);
int dlist_append(dlist_t *dst, dlist_t *src);

#endif
