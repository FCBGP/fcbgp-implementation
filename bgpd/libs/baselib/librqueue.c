#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "librqueue.h"

rqueue_t *rqueue_create(int qsize, int isize, int overlay)
{
    rqueue_t *rq;

    rq = malloc(sizeof(rqueue_t) + qsize * isize);
    if (rq == NULL) {
        return NULL;
    }

    memset(rq->qbuffer, 0, qsize * isize);

    rq->qsize = qsize;
    rq->overlay = !!overlay;
    rq->isize = isize;
    rq->head = 0;
    rq->tail = 0;

    return rq;
}

void rqueue_clear(rqueue_t * rq)
{
    rq->head = rq->tail = 0;
}

void rqueue_destroy(rqueue_t * rq)
{
    free(rq);
}

int rqueue_capacity(rqueue_t * rq)
{
    return rq->qsize - 1;
}

int rqueue_used(rqueue_t * rq)
{
    return (rq->qsize + rq->tail - rq->head) % rq->qsize;
}

int rqueue_isfull(rqueue_t * rq)
{
    return (rqueue_used(rq) == rqueue_capacity(rq));
}

int rqueue_isempty(rqueue_t * rq)
{
    return (rq->tail == rq->head);
}

int rqueue_index(rqueue_t * rq, int i)
{
    return (rq->qsize + rq->head + i) % rq->qsize;
}

int rqueue_enqueue(rqueue_t * rq, void *value)
{
    int offset = rq->tail * rq->isize;
    if (rqueue_isfull(rq)) {
        if (rq->overlay) {
            rq->head = (rq->head + 1) % rq->qsize;
            memcpy(rq->qbuffer + offset, value, rq->isize);
            rq->tail = (rq->tail + 1) % rq->qsize;
            return offset;
        }
        return -ENOSPC;
    }

    memcpy(rq->qbuffer + offset, value, rq->isize);
    rq->tail = (rq->tail + 1) % rq->qsize;
    return offset;
}

int rqueue_dequeue(rqueue_t * rq, void *value)
{
    if (rqueue_isempty(rq))
        return -ENOENT;

    memcpy(value, rq->qbuffer + rq->head * rq->isize, rq->isize);
    rq->head = (rq->head + 1) % rq->qsize;
    return 0;
}

int rqueue_foreach(rqueue_t *rq, int *cursor, int (*handler)(int i, int idx, void *data, void *user), void *user)
{
    int i, idx;
    int ret = -1;
    int cnt = 0;
    int used = rqueue_used(rq);

    if (handler == NULL) {
        return 0;
    }

    for (i=*cursor; i<used; i++) {
        idx = rqueue_index(rq, i);
        ret = handler(i, idx, rq->qbuffer + idx * rq->isize, user);
        switch (ret) {
        case -1: goto out;
        case 0: break;
        case 1: cnt++; break;
        case 2: cnt++; goto out;
        }
    }

out:
    *cursor = i;
    return cnt;
}

int rqueue_foreach_reverse(rqueue_t *rq, int *cursor, int (*handler)(int i, int idx, void *data, void *user), void *user)
{
    int i, idx;
    int ret = -1;
    int cnt = 0;
    int used = rqueue_used(rq);

    if (handler == NULL) {
        return 0;
    }

    for (i=*cursor; i<used; i++) {
        idx = rqueue_index(rq, used - i - 1);
        ret = handler(i, idx, rq->qbuffer + idx * rq->isize, user);
        switch (ret) {
        case -1: goto out;
        case 0: break;
        case 1: cnt++; break;
        case 2: cnt++; goto out;
        }
    }

out:
    *cursor = i;
    return cnt;
}

