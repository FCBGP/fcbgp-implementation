#ifndef _LIBLISTENER_H_
#define _LIBLISTENER_H_

#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "liblist.h"

#define MAX_FD_VALUE 1024

#define LISTEN_EVENT_READ 0x01
#define LISTEN_EVENT_WRITE 0x02
#define LISTEN_EVENT_EXCEPT 0x04
#define LISTEN_EVENT_TIMEOUT 0x08
#define LISTEN_EVENT_PREEMPT 0x10
#define LISTEN_EVENT_MARKED 0x20

#define LISTEN_EVENT_RT (LISTEN_EVENT_READ | LISTEN_EVENT_TIMEOUT)
#define LISTEN_EVENT_RWT (LISTEN_EVENT_READ | LISTEN_EVENT_WRITE | LISTEN_EVENT_TIMEOUT)

typedef enum {
    LISTEN_F_NONE = 0x00,
    LISTEN_F_QUIT = 0x01,
    LISTEN_F_MARKED = 0x02
} listen_flag_t;

typedef unsigned short listen_event_t;
typedef struct listener_st listener_t;

typedef int (listener_handler_t) (listener_t * listener, listen_event_t event);
typedef int (listener_enumerator_t) (listener_t * listener, void *arg);
typedef int (listener_remover_t) (listener_t * listener);
typedef int (listener_interrupter_t) (void *arg);

struct listener_st {
    struct list_head node;

    // File descriptor (if any) of listener; <0 means no file descriptor.
    int fd;

    // Indicator to handle garbage-collection:
    // -1: the listener can be safely freed upon removal
    // 0:  may be removed by the callback, but will not be freed  until callback returns
    // >0: has been removed, and should be freed when the callback returns
    int delayFree;

    // Number of seconds after which this listener will receive a timeout message (-1 means no timeout).
    time_t timeout;

    // real time when this listener will receive a timeout message (set to timeout + current time).
    time_t expiration;

    // Map of event types this listener wants to handle.
    listen_event_t type;

    // Function to call when event happens to listener.
    listener_handler_t *handler;

    // Pointer back to structure containing list of all listeners.
    void *parent;

    // User-defined tag (optional).
    void *tag;
};

typedef struct listenerset_st {
    // File descriptor set for use by select to wait for read events.
    fd_set rdFds;

    // File descriptor set for use by select to waiti for write events.
    fd_set wrFds;

    // File descriptor set for use by select to wait for exception events.
    fd_set excFds;

    // Copy of rdFds to pass in to select.
    fd_set rdFds2;

    // Copy of wrFds to pass in to select.
    fd_set wrFds2;

    // Copy of excFds to pass in to select.
    fd_set excFds2;

    // Largest file descriptor value as needed by select().
    int lastFd;

    // Flags that may modify the processing loop for this set.
    listen_flag_t flags;

    // An array of listeners as indexed by their file descriptors.
    listener_t *fdIndex[MAX_FD_VALUE + 1];

    // Minimum amount of time we should wait in select based on the smallest time left for any listener in this set.
    time_t minExpiration;

    // Linked list of all the listeners in this set.
    struct list_head list;

    // Callback to be called if it is desired to be notified of interrupted system calls.
    // This value can be NULL.
    listener_interrupter_t *interrupter;

    // Argument that should be passed along to the interrupt handler.
    void *interrupt_arg;

    // Callback to be called for any listeners removed from this set.
    // This value can be NULL.
    listener_remover_t *remover;
} listenerset_t;

extern listenerset_t *listenerset_create(void);
extern void listenerset_destroy(listenerset_t *set);

extern int listenerset_init(listenerset_t * set);
extern int listenerset_loop(listenerset_t * set);
extern int listenerset_quit(listenerset_t * set);
extern int listenerset_count(listenerset_t * set);
extern int listenerset_clear(listenerset_t * set);
extern int listenerset_enumerate(listenerset_t * set, listener_enumerator_t * enumerator, void *arg);
extern listener_t *listenerset_add(listenerset_t * set, int fd, listener_handler_t * handler, listen_event_t type, void *tag, time_t timeout);
#define listenerset_addtimer(set, handler, tag, timeout) listenerset_add(set, -1, handler, LISTEN_EVENT_TIMEOUT, tag, timeout)
extern int listenerset_update_remover(listenerset_t * set, listener_remover_t * remover);
extern int listenerset_update_interrupter(listenerset_t * set, listener_interrupter_t * interrupter, void *arg);
extern int listenerset_mark(listenerset_t * set);

extern int listener_remove(listener_t * listener);
extern int listener_set_fd(listener_t * listener, int fd);
extern int listener_set_handler(listener_t * listener, listener_handler_t * handler);
extern int listener_set_timeout(listener_t * listener, time_t timeout);
extern int listener_set_event(listener_t * listener, listen_event_t type);

#endif
