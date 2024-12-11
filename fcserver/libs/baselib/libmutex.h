#ifndef LIBMUTEX_H
#define LIBMUTEX_H

#include <pthread.h>

typedef pthread_mutex_t mutex_t;

static inline int mutex_init(mutex_t* mutex)
{
    return pthread_mutex_init(mutex, NULL);
}

static inline int mutex_destroy(mutex_t* mutex)
{
    return pthread_mutex_destroy(mutex);
}

static inline int mutex_lock(mutex_t* mutex)
{
    return pthread_mutex_lock(mutex);
}

static inline int mutex_trylock(mutex_t* mutex)
{
    return pthread_mutex_trylock(mutex);
}

static inline int mutex_unlock(mutex_t* mutex)
{
    return pthread_mutex_unlock(mutex);
}

#endif
