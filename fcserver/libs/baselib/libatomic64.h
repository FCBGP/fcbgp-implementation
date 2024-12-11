#ifndef LIBATOMIC64_H
#define LIBATOMIC64_H 1

#include "libspinlock.h"
#include <stdint.h>

typedef struct atomic64_st
{
    volatile uint64_t counter;
    spinlock_t spinlock;
} atomic64_t;

static inline void atomic64_init(atomic64_t* v)
{
    v->counter = 0;
    spinlock_init(&(v->spinlock));
}

static inline void atomic64_exit(atomic64_t* v)
{
    spinlock_destroy(&(v->spinlock));
}

static inline uint64_t atomic64_add_return(atomic64_t* v, int i)
{
    uint64_t res;

    spinlock_lock(&(v->spinlock));
    v->counter += i;
    res = v->counter;
    spinlock_unlock(&(v->spinlock));

    return res;
}

static inline uint64_t atomic64_sub_return(atomic64_t* v, int i)
{
    uint64_t res;

    spinlock_lock(&(v->spinlock));
    v->counter -= i;
    res = v->counter;
    spinlock_unlock(&(v->spinlock));

    return res;
}

static inline uint64_t atomic64_read(atomic64_t* v) { return v->counter; }

static inline void atomic64_set(atomic64_t* v, int i)
{
    spinlock_lock(&(v->spinlock));
    v->counter = i;
    spinlock_unlock(&(v->spinlock));
}

static inline uint64_t atomic64_add(atomic64_t* v, int i)
{
    return atomic64_add_return(v, i);
}

static inline uint64_t atomic64_sub(atomic64_t* v, int i)
{
    return atomic64_sub_return(v, i);
}

static inline uint64_t atomic64_inc(atomic64_t* v)
{
    return atomic64_add_return(v, 1);
}

static inline uint64_t atomic64_dec(atomic64_t* v)
{
    return atomic64_sub_return(v, 1);
}

static inline uint64_t atomic64_dec_and_test(atomic64_t* v)
{
    return atomic64_sub_return(v, 1) == 0;
}

#endif
