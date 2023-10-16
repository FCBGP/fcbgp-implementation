#ifndef __LIBREQ_H__
#define __LIBREQ_H__

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/un.h>

#include "libmutex.h"
#include "libstream.h"
#include "libmsgpack.h"

typedef struct req_ctx_st {
    int fd;
    char *name;
    char *address;
    stream_t *input;
    stream_t *output;
    mpack_ctx_t encoder;
    mpack_ctx_t decoder;
    struct sockaddr_un sockaddr;
    mutex_t mutex;
} req_ctx_t;

extern req_ctx_t *req_create(char *name, char *address);
extern req_ctx_t *req_duplicate(req_ctx_t *req);
extern void req_destroy(req_ctx_t *ctx);
extern void req_switch(req_ctx_t *ctx, char *address);
extern int req_recvmsg(req_ctx_t *ctx);
extern int req_sendmsg(req_ctx_t *ctx);
extern int req_request(req_ctx_t *ctx);
extern int req_checkresult(req_ctx_t *ctx);

#endif
