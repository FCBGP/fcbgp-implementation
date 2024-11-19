#ifndef LIBCONDITION_H
#define LIBCONDITION_H

#include <pthread.h>

#include "libmutex.h"

typedef pthread_cond_t condition_t;

static inline int condition_init(condition_t *cond)
{
    return pthread_cond_init(cond, NULL);
}

static inline int condition_destroy (condition_t *cond)
{
    return pthread_cond_destroy(cond);
}

static inline int condition_signal(condition_t *cond)
{
    return pthread_cond_signal(cond);
}

static inline int condition_broadcast (condition_t *cond)
{
    return pthread_cond_broadcast(cond);
}

static inline int condition_wait(condition_t *cond, mutex_t *mutex)
{
    return pthread_cond_wait(cond, mutex);
}

static inline int condition_timedwait(condition_t *cond, mutex_t *mutex, struct timespec *tval)
{
    return pthread_cond_timedwait(cond, mutex, tval);
}

#endif
