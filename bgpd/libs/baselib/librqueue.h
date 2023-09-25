#ifndef _LIBRQUEUE_H_
#define _LIBRQUEUE_H_ 1

#include <stdint.h>

typedef struct rqueue_st {
    /*
     * the total size of the ring queue, the capacity of the rq is $qsize -1$,
     */
    uint32_t qsize:31;

    /*
     * overlay indicates the buffer can be overlapped when queue is full.
     */
    uint32_t overlay:1;

    /* the item size of the data in the ring queue */
    uint32_t isize;

    /* current read index */
    uint32_t head;

    /* current write index */
    uint32_t tail;

    /* the buffer of data */
    uint8_t qbuffer[0];
} rqueue_t;

extern rqueue_t *rqueue_create(int qsize, int isize, int overlay);
extern void rqueue_clear(rqueue_t *rq);
extern void rqueue_destroy(rqueue_t *rq);
extern int rqueue_capacity(rqueue_t *rq);
extern int rqueue_used(rqueue_t *rq);
extern int rqueue_isfull(rqueue_t *rq);
extern int rqueue_isempty(rqueue_t *rq);
extern int rqueue_index(rqueue_t *rq, int i);
extern int rqueue_enqueue(rqueue_t *rq, void *value);
extern int rqueue_dequeue(rqueue_t *rq, void *value);
extern int rqueue_foreach(rqueue_t *rq, int *cursor, int (*handler)(int i, int idx, void *data, void *user), void *user);
extern int rqueue_foreach_reverse(rqueue_t *rq, int *cursor, int (*handler)(int i, int idx, void *data, void *user), void *user);

#endif
