#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include "libdiag.h"
#include "liblistener.h"

#if 0
#ifdef HAVE_SYS_UPTIME
#include <uptime.h>
#define curtime() (long)uptime()
#else
#define curtime() (long)time(NULL)
#endif
#else
static inline time_t curtime(void)
{
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return now.tv_sec;
}
#endif

#ifdef LISTENER_DEBUG
void listener_dump(listener_t * listener)
{
    if (listener) {
        fprintf(stderr, "listener (%p): fd=%d type=%#02x handler=%p tag=%p timeout=%ld expiration=%ld\n",
            listener, listener->fd, listener->type, listener->handler, listener->tag, listener->timeout,
            listener->expiration);
    } else {
        fprintf(stderr, "listener (NULL)\n");
    }
}

void listener_set_dump(listenerset_t * set)
{
    listener_t *listener;

    if (set == NULL) {
        return;
    }

    fprintf(stderr, "listenerset (%p):\n", set);
    list_for_each_entry(listener, &set->list, node) {
        listener_dump(listener);
    }
}
#endif

static int listener_refresh_timeout(listener_t * listener, void *arg)
{
    if (listener->timeout > 0) {
        listener->expiration = curtime() + listener->timeout;
    } else {
        listener->expiration = 0;
    }

    return 0;
}

/*
 * find the minimum timeout across each listener and handle
 * preempt event creation.
 */
static int listener_preempt(listener_t * listener, void *arg)
{
    listenerset_t *set = arg;

    if (listener->expiration > 0) {
        if (listener->expiration <= curtime()) {
            if (listener->handler) {
                (listener->handler) (listener, LISTEN_EVENT_TIMEOUT);
                if (listener->delayFree > 0) {
                    return 0;
                } else {
                    listener->delayFree = -1;
                }
            }
            listener_refresh_timeout(listener, NULL);
        }

        if (set->minExpiration == 0 || listener->expiration < set->minExpiration) {
            set->minExpiration = listener->expiration;
        }
    }

    if (listener->type & LISTEN_EVENT_PREEMPT) {
        if (listener->handler) {
            (listener->handler) (listener, LISTEN_EVENT_PREEMPT);
            if (listener->delayFree > 0) {
                return 0;
            }
        }
    }

    return 0;
}

static void listener_check(listener_t * listener, int marked)
{
    listen_event_t type = 0;
    listenerset_t *set = listener->parent;

    if (!marked && listener->fd < 0) {
        return;
    }

    if (marked) {
        if (listener->type & LISTEN_EVENT_MARKED) {
            type |= LISTEN_EVENT_MARKED;
        } else {
            return;
        }
    } else {
        if (FD_ISSET(listener->fd, &set->rdFds2)) {
            FD_CLR(listener->fd, &set->rdFds2);
            type |= LISTEN_EVENT_READ;
        } else if (FD_ISSET(listener->fd, &set->wrFds2)) {
            FD_CLR(listener->fd, &set->wrFds2);
            type |= LISTEN_EVENT_WRITE;
        } else if (FD_ISSET(listener->fd, &set->excFds2)) {
            FD_CLR(listener->fd, &set->excFds2);
            type |= LISTEN_EVENT_EXCEPT;
        }
    }

    if (type) {
        listener_refresh_timeout(listener, NULL);
        if (listener->handler) {
            listener->delayFree = 0;
            (*listener->handler) (listener, type);
            if (listener->delayFree > 0) {
                list_del(&listener->node);
                free(listener);
                return;
            } else {
                listener->delayFree = -1;
            }
        }
    }

    return;
}

int listenerset_quit(listenerset_t * set)
{
    if (set == NULL) {
        return -EINVAL;
    }

    set->flags |= LISTEN_F_QUIT;
    return 0;
}

int listenerset_loop(listenerset_t * set)
{
    int n;
    struct timeval tv;
    struct timeval *tvp;
    listener_t **lp;

    if (set == NULL) {
        return 0;
    }

    listenerset_enumerate(set, listener_refresh_timeout, NULL);
    while (!list_empty(&set->list) && !(set->flags & LISTEN_F_QUIT)) {
        set->minExpiration = 0;
        listenerset_enumerate(set, listener_preempt, set);
        if (list_empty(&set->list) || set->flags & LISTEN_F_QUIT) {
            DIAG_INFO("listener loop will exit.\n");
            return 0;
        }

        if (set->minExpiration > 0) {
            tv.tv_sec = set->minExpiration - curtime();
            if (tv.tv_sec < 0) {
                tv.tv_sec = 0;
                tv.tv_usec = 1;
            } else {
                tv.tv_usec = 0;
            }
            tvp = &tv;
        } else {
            tvp = NULL;
        }
        memcpy(&set->rdFds2, &set->rdFds, sizeof(set->rdFds));
        memcpy(&set->wrFds2, &set->wrFds, sizeof(set->wrFds));
        memcpy(&set->excFds2, &set->excFds, sizeof(set->excFds));

        if (!(set->flags & LISTEN_F_MARKED)) {
            n = select(set->lastFd + 1, &set->rdFds2, &set->wrFds2, &set->excFds2, tvp);
            if (n < 0) {
                if (errno == EINTR) {
                    if (set->interrupter)
                        set->interrupter(set->interrupt_arg);
                } else if (errno != EINTR) {
                    DIAG_ERROR("listener loop select failed: %m.\n");
                }
            } else if (n > 0) {
                for (n = 0, lp = set->fdIndex; n <= set->lastFd; n++, lp++) {
                    if (*lp) {
                        listener_check(*lp, 0);
                    }
                }
            }
        } else {
            listener_t *l;
            set->flags &= ~LISTEN_F_MARKED;
            list_for_each_entry(l, &set->list, node) {
                if (l->type & LISTEN_EVENT_MARKED) {
                    listener_check(l, 1);
                }
            }
        }
    }

    return 0;
}

int listener_remove(listener_t * listener)
{
    listenerset_t *set;
    set = listener->parent;

    if (set->remover) {
        set->remover(listener);
    }
    if (listener->fd >= 0) {
        listener_set_event(listener, 0);
        set->fdIndex[listener->fd] = NULL;
        if (listener->fd == set->lastFd) {
            while (--set->lastFd >= 0 && set->fdIndex[set->lastFd] == NULL);
        }
    }
    if (listener->delayFree < 0) {
        list_del(&listener->node);
        free(listener);
    } else if (listener->delayFree == 0) {
        listener->delayFree++;
    }

    return 0;
}

int listenerset_clear(listenerset_t * set)
{
    listener_t *listener;
    listener_t *next_listener;

    if (set == NULL) {
        return 0;
    }

    list_for_each_entry_safe(listener, next_listener, &set->list, node) {
        listener_remove(listener);
    }

    return 0;
}

int listener_set_handler(listener_t * listener, listener_handler_t * handler)
{
    listener->handler = handler;
    return 0;
}

int listener_set_fd(listener_t * listener, int fd)
{
    listenerset_t *set;
    set = listener->parent;
    if (listener->fd >= 0) {
        set->fdIndex[listener->fd] = NULL;
    }
    if (listener->fd == set->lastFd) {
        while (--set->lastFd >= 0 && set->fdIndex[set->lastFd] == NULL);
    }
    if (fd >= 0) {
        set->fdIndex[fd] = listener;
        if (fd > set->lastFd) {
            set->lastFd = fd;
        }
    }
    listener->fd = fd;

    return 0;
}

int listener_set_event(listener_t * listener, listen_event_t type)
{
    listenerset_t *set;
    set = listener->parent;
    if (listener->type == type) {
        return 0;
    }
    if (listener->fd >= 0) {
        FD_CLR(listener->fd, &set->rdFds);
        FD_CLR(listener->fd, &set->rdFds2);
        FD_CLR(listener->fd, &set->wrFds);
        FD_CLR(listener->fd, &set->wrFds2);
        FD_CLR(listener->fd, &set->excFds);
        FD_CLR(listener->fd, &set->excFds2);
    }
    listener->type = type;
    if (listener->fd > -1) {
        if (type & LISTEN_EVENT_READ) {
            FD_SET(listener->fd, &set->rdFds);
        }
        if (type & LISTEN_EVENT_WRITE) {
            FD_SET(listener->fd, &set->wrFds);
        }
        if (type & LISTEN_EVENT_EXCEPT) {
            FD_SET(listener->fd, &set->excFds);
        }
    }

    return 0;
}

int listener_set_timeout(listener_t * listener, time_t timeout)
{
    listener->timeout = timeout;
    listener_refresh_timeout(listener, NULL);
    return 0;
}

int listenerset_init(listenerset_t * set)
{
    if (set == NULL) {
        return -EINVAL;
    }

    set->remover = NULL;
    FD_ZERO(&set->rdFds);
    FD_ZERO(&set->wrFds);
    FD_ZERO(&set->excFds);
    FD_ZERO(&set->rdFds2);
    FD_ZERO(&set->wrFds2);
    FD_ZERO(&set->excFds2);
    set->lastFd = -1;
    memset(&set->fdIndex, 0, sizeof(set->fdIndex));
    INIT_LIST_HEAD(&set->list);
    set->minExpiration = 0;
    set->interrupter = NULL;
    set->interrupt_arg = NULL;
    set->flags = LISTEN_F_NONE;

    return 0;
}

listenerset_t *listenerset_create(void)
{
    listenerset_t *set = NULL;

    set = calloc(1, sizeof(listenerset_t));
    if (set == NULL) {
        return NULL;
    }

    listenerset_init(set);
    return set;
}

void listenerset_destroy(listenerset_t *set)
{
    if (set == NULL) {
        return;
    }

    listenerset_clear(set);

    free(set);
    return;
}

listener_t *listenerset_add(listenerset_t * set, int fd, listener_handler_t * handler, listen_event_t type, void *tag, time_t timeout)
{
    listener_t *listener = NULL;

    if (set == NULL) {
        errno = EINVAL;
        return NULL;
    }

    if (fd > MAX_FD_VALUE) {
        errno = EMFILE;
        return NULL;
    }

    listener = (listener_t *) calloc(1, sizeof *listener);
    if (!listener) {
        return NULL;
    }

    listener->parent = set;
    listener->fd = fd;
    listener->handler = handler;
    listener->tag = tag;
    listener->timeout = listener->expiration = 0;
    listener->type = 0;
    listener->delayFree = -1;

    listener_set_event(listener, type);
    if (type & LISTEN_EVENT_TIMEOUT) {
        listener_set_timeout(listener, timeout);
    }

    if (fd >= 0) {
        set->fdIndex[fd] = listener;
        if (fd > set->lastFd) {
            set->lastFd = fd;
        }
    }

    my_list_add(&listener->node, &set->list);

    return listener;
}

int listenerset_count(listenerset_t * set)
{
    listener_t *listener;
    unsigned long count = 0;

    if (set == NULL) {
        return -EINVAL;
    }

    list_for_each_entry(listener, &set->list, node) {
        count++;
    }

    return count;
}

int listenerset_enumerate(listenerset_t * set, listener_enumerator_t * enumerator, void *arg)
{
    listener_t *listener;
    listener_t *tmp_listener;

    if (set == NULL || enumerator == NULL) {
        return -EINVAL;
    }

    list_for_each_entry_safe(listener, tmp_listener, &set->list, node) {
        listener->delayFree = 0;
        (*enumerator) (listener, arg);
        if (listener->delayFree > 0) {
            list_del(&listener->node);
            free(listener);
            continue;
        }
        listener->delayFree = -1;
    }

    return 0;
}

int listenerset_update_remover(listenerset_t * set, listener_remover_t * remover)
{
    if (set == NULL) {
        return -EINVAL;
    }

    set->remover = remover;
    return 0;
}

int listenerset_update_interrupter(listenerset_t * set, listener_interrupter_t * interrupter, void *arg)
{
    if (set == NULL) {
        return -EINVAL;
    }

    set->interrupter = interrupter;
    set->interrupt_arg = arg;
    return 0;
}

/*
 * For the next iteration through select(), skip the call and process only
 * those listeners that are marked to handle LISTEN_EVENT_MARKED events.
 */
int listenerset_mark(listenerset_t * set)
{
    if (set == NULL) {
        return -EINVAL;
    }

    set->flags |= LISTEN_F_MARKED;
    return 0;
}
