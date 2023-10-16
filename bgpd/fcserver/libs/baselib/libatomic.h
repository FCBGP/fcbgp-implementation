#ifndef LIBATOMIC_H
#define LIBATOMIC_H 1

#include <stdint.h>
#include "libspinlock.h"

#ifndef ARCH_ATOMIC_NO_NICKNAMES
#undef atomic_add
#undef atomic_sub
#endif

typedef struct atomic_st {
    volatile uint32_t counter;
    spinlock_t spinlock;
} atomic_t;

static inline void atomic_init(atomic_t * v)
{
    v->counter = 0;
    spinlock_init(&(v->spinlock));
}

static inline void atomic_exit(atomic_t * v)
{
    spinlock_destroy(&(v->spinlock));
}

static inline uint32_t atomic_add_return(atomic_t * v, int i)
{
    uint32_t res;

    spinlock_lock(&(v->spinlock));
    v->counter += i;
    res = v->counter;
    spinlock_unlock(&(v->spinlock));

    return res;
}

static inline uint32_t atomic_sub_return(atomic_t * v, int i)
{
    uint32_t res;

    spinlock_lock(&(v->spinlock));
    v->counter -= i;
    res = v->counter;
    spinlock_unlock(&(v->spinlock));

    return res;
}

static inline uint32_t atomic_read(atomic_t * v)
{
    return v->counter;
}

static inline void atomic_set(atomic_t * v, int i)
{
    spinlock_lock(&(v->spinlock));
    v->counter = i;
    spinlock_unlock(&(v->spinlock));
}

static inline uint32_t atomic_add(atomic_t * v, int i)
{
    return atomic_add_return(v, i);
}

static inline uint32_t atomic_sub(atomic_t * v, int i)
{
    return atomic_sub_return(v, i);
}

static inline uint32_t atomic_inc(atomic_t * v)
{
    return atomic_add_return(v, 1);
}

static inline uint32_t atomic_dec(atomic_t * v)
{
    return atomic_sub_return(v, 1);
}

static inline uint32_t atomic_dec_and_test(atomic_t * v)
{
    return atomic_sub_return(v, 1) == 0;
}

#endif
