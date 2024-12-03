#ifndef __LIBREP_H__
#define __LIBREP_H__

#include <errno.h>
#include <linux/un.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "libcondition.h"
#include "libdispatch.h"
#include "liblistener.h"
#include "libmbs.h"
#include "libmsgpack.h"
#include "libmutex.h"
#include "libstream.h"

typedef struct rep_ctx_st rep_ctx_t;

typedef struct rep_worker_st
{
    int cid;
    int idx;
    int state;
    pthread_t tid;

    rep_ctx_t* ctx;
    stream_t* input;
    stream_t* output;
    mpack_ctx_t encoder;
    mpack_ctx_t decoder;
} rep_worker_t;

#define MAX_COMMAND_SIZE 1024
typedef int (*rep_handler_t)(rep_worker_t* worker);

struct rep_ctx_st
{
    char* name;
    char* address;
    char pidfile[128];

    int fd;
    int workers;
    struct sockaddr_un sockaddr;

    mutex_t mutex;
    condition_t condition;

    rep_worker_t* workertbl;
    dispatch_ctx_t* dispatch;
    listenerset_t* listenerset;
};

extern rep_ctx_t* rep_create(char* name, int workers, char* address);
extern void rep_destroy(rep_ctx_t* ctx);
extern void rep_freemsg(rep_worker_t* worker);
extern int rep_recvmsg(rep_worker_t* worker);
extern int rep_sendmsg(rep_worker_t* worker);
extern int rep_packerr(rep_worker_t* worker, int error);
extern int rep_senderr(rep_worker_t* worker, int error, char* fmt, ...);
extern int rep_packok(rep_worker_t* worker);
extern int rep_sendok(rep_worker_t* worker, char* fmt, ...);
extern int rep_start(rep_ctx_t* ctx);
extern int rep_loop(rep_ctx_t* ctx);
extern int rep_add_timer(rep_ctx_t* ctx, int timeout,
                         listener_handler_t handler);

#endif
