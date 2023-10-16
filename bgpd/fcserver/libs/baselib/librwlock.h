#ifndef LIBRWLOCK_H
#define LIBRWLOCK_H

#include <time.h>
#include <pthread.h>

typedef pthread_rwlock_t rwlock_t;

static inline int rwlock_init(rwlock_t *rwlock)
{
    return pthread_rwlock_init(rwlock, NULL);
}

static inline int rwlock_destroy(rwlock_t *rwlock)
{
    return pthread_rwlock_destroy(rwlock);
}

static inline int rwlock_rdlock(rwlock_t *rwlock)
{
    return pthread_rwlock_rdlock(rwlock);
}

static inline int rwlock_tryrdlock(rwlock_t *rwlock)
{
    return pthread_rwlock_tryrdlock(rwlock);
}

static inline int rwlock_wrlock(rwlock_t *rwlock)
{
    return pthread_rwlock_wrlock(rwlock);
}

static inline int rwlock_trywrlock(rwlock_t *rwlock)
{
    return pthread_rwlock_trywrlock(rwlock);
}

static inline int rwlock_unlock(rwlock_t *rwlock)
{
    return pthread_rwlock_unlock(rwlock);
}

static inline int rwlock_rdunlock(rwlock_t *rwlock)
{
    return pthread_rwlock_unlock(rwlock);
}

static inline int rwlock_wrunlock(rwlock_t *rwlock)
{
    return pthread_rwlock_unlock(rwlock);
}

#endif
