#ifndef __LIBTHREAD_H__
#define __LIBTHREAD_H__

#include <stdlib.h>
#include <string.h>
#include <pthread.h>

typedef int (*thread_handler_t)(void *);

#define THREAD_FLAG_RUNNING 0x0001
#define THREAD_FLAG_PAUSED 0x0002
#define THREAD_FLAG_DETACHED 0x0004
#define THREAD_FLAG_STACKSIZE 0x0008

typedef struct thread_st {
    int size;
    int flags;
    pthread_t pid;
    char *name;
    thread_handler_t handler;
    char arg[0];
} thread_t;

static inline void *thread_handler(void *arg)
{
    int ret;
    thread_t *thread = (thread_t *) arg;

    thread->flags |= THREAD_FLAG_RUNNING;
    pthread_setname_np(pthread_self(), thread->name);

    while (1) {
        if (!(thread->flags & THREAD_FLAG_RUNNING)) {
            break;
        }

        if (thread->flags & THREAD_FLAG_PAUSED) {
            continue;
        }

        ret = thread->handler(thread->arg);
        if (ret <= 0) {
            break;
        }
    }

    if (thread->flags & THREAD_FLAG_DETACHED) {
        free(thread);
    }

    pthread_exit(NULL);
    return NULL;
}

static inline thread_t *thread_create(char *name, int flags, thread_handler_t handler, void *arg, int size)
{
    int ret;
    pthread_attr_t attr;

    pthread_attr_init(&attr);
    if (flags & THREAD_FLAG_DETACHED) {
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    }

    if (flags & THREAD_FLAG_STACKSIZE) {
        pthread_attr_setstacksize(&attr, (flags & 0xFFFF0000) >> 16);
    }

    thread_t *thread = malloc(sizeof(thread_t) + size);
    if (thread == NULL) {
        pthread_attr_destroy(&attr);
        return NULL;
    }

    thread->size = size;
    thread->name = name;
    thread->handler = handler;
    thread->flags = (flags & (~(THREAD_FLAG_RUNNING | THREAD_FLAG_PAUSED)));

    if (arg && size) {
        memcpy(thread->arg, arg, size);
    }

    ret = pthread_create(&thread->pid, &attr, thread_handler, (void *) thread);
    if (ret) {
        pthread_attr_destroy(&attr);
        free(thread);
        return NULL;
    }

    pthread_setname_np(thread->pid, name);

    while (1) {
        if (thread->flags & THREAD_FLAG_RUNNING) {
            break;
        }
        usleep(100);
    }

    pthread_attr_destroy(&attr);
    return thread;
}

static inline void thread_destroy(thread_t *thread)
{
    if (thread) {
        if (!(thread->flags & THREAD_FLAG_DETACHED)) {
            thread->flags &= (~THREAD_FLAG_RUNNING);
            pthread_join(thread->pid, NULL);
            free(thread);
        }
    }
}

static inline void thread_pause(thread_t *thread)
{
    if (thread) {
        thread->flags |= THREAD_FLAG_PAUSED;
    }
}

static inline void thread_resume(thread_t *thread)
{
    if (thread) {
        thread->flags &= (~THREAD_FLAG_PAUSED);
    }
}

static inline int thread_call(thread_handler_t handler, void *arg, int size)
{
    thread_t *thread = thread_create((char *)__func__, THREAD_FLAG_DETACHED, handler, arg, size);
    if (thread) {
        while (1) {
            if (thread->flags & THREAD_FLAG_RUNNING) {
                break;
            }

            sleep(1);
        }

        thread_destroy(thread);
        return 0;
    }

    return -1;
}

#endif
