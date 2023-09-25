#ifndef __LIBDISPATCH_H__
#define __LIBDISPATCH_H__

#include "libmpse.h"
#include "libspinlock.h"

typedef struct dispatch_command_st {
    char *command;
    void *handler;
} dispatch_command_t;

typedef struct dispatch_ctx_st {
    mpse_t commands;
    spinlock_t spinlock;
    mpse_matchers_t matchers;
} dispatch_ctx_t;

extern dispatch_ctx_t *dispatch_create(void);
extern void dispatch_destroy(dispatch_ctx_t *ctx);
extern int dispatch_register_command(dispatch_ctx_t *ctx, char *command, void *handler);
extern int dispatch_register_commands(dispatch_ctx_t *ctx, dispatch_command_t *commands);
extern int dispatch_prepare(dispatch_ctx_t *ctx);
extern void *dispatch(dispatch_ctx_t *ctx, char *command, int len);

#endif
