#ifndef LIBSPINLOCK_H
#define LIBSPINLOCK_H

#include <pthread.h>

typedef pthread_spinlock_t spinlock_t;

static inline int spinlock_init(spinlock_t* spinlock)
{
    return pthread_spin_init(spinlock, 0);
}

static inline int spinlock_destroy(spinlock_t* spinlock)
{
    return pthread_spin_destroy(spinlock);
}

static inline int spinlock_lock(spinlock_t* spinlock)
{
    return pthread_spin_lock(spinlock);
}

static inline int spinlock_trylock(spinlock_t* spinlock)
{
    return pthread_spin_trylock(spinlock);
}

static inline int spinlock_unlock(spinlock_t* spinlock)
{
    return pthread_spin_unlock(spinlock);
}

#endif
