#include "libdiag.h"
#include "libdispatch.h"

dispatch_ctx_t *dispatch_create(void)
{
    int ret;

    dispatch_ctx_t *ctx = malloc(sizeof(dispatch_ctx_t));
    if (ctx == NULL) {
        return NULL;
    }

    mpse_alg_init();

    ret = mpse_init(&ctx->commands, MPSE_ALG_AC);
    if (ret < 0) {
        free(ctx);
        return NULL;
    }

    ret = mpse_matchers_init(&ctx->matchers, 1, 1, 0);
    if (ret < 0) {
        mpse_fini(&ctx->commands);
        free(ctx);
        return NULL;
    }

    spinlock_init(&ctx->spinlock);
    return ctx;
}

void dispatch_destroy(dispatch_ctx_t *ctx)
{
    if (ctx) {
        spinlock_lock(&ctx->spinlock);
        mpse_matchers_fini(&ctx->matchers);
        mpse_fini(&ctx->commands);
        mpse_alg_fini();
        spinlock_unlock(&ctx->spinlock);

        spinlock_destroy(&ctx->spinlock);
        free(ctx);
    }
}

int dispatch_register_command(dispatch_ctx_t *ctx, char *command, void *handler)
{
    int ret;

    spinlock_lock(&ctx->spinlock);
    ret = mpse_add(&ctx->commands, 0, (uint8_t *)command, strlen(command),
            MPSE_PATTERN_FLAG_OFFSET0 | MPSE_PATTERN_FLAG_OFFSETX, NULL, handler);
    spinlock_unlock(&ctx->spinlock);

    return ret;
}

int dispatch_register_commands(dispatch_ctx_t *ctx, dispatch_command_t *commands)
{
    int ret = 0;
    dispatch_command_t *cmd = NULL;

    if(ctx == NULL || commands == NULL) {
        return -EINVAL;
    }

    for (cmd=commands; cmd->command; cmd++) {
        ret = dispatch_register_command(ctx, cmd->command, cmd->handler);
        if (ret < 0) {
            return ret;
        }
    }

    return ret;
}

int dispatch_prepare(dispatch_ctx_t *ctx)
{
    int ret;

    spinlock_lock(&ctx->spinlock);
    ret = mpse_prepare(&ctx->commands);
    spinlock_unlock(&ctx->spinlock);

    return ret;
}

void *dispatch(dispatch_ctx_t *ctx, char *command, int len)
{
    int ret = -1;
    void *handler = NULL;

    spinlock_lock(&ctx->spinlock);
    mpse_matchers_flush(&ctx->matchers);

    ret = mpse_search(&ctx->commands, (uint8_t *)command, len, &ctx->matchers, 0);
    if (ret <= 0) {
        spinlock_unlock(&ctx->spinlock);
        DIAG_ERROR("command %s is not support.\n", command);
        return NULL;
    }

    if (ret > 1) {
        spinlock_unlock(&ctx->spinlock);
        DIAG_ERROR("command %s has a lot of matchers.\n", command);
        return NULL;
    }

    handler = ctx->matchers.classes[0].res[0].tag;
    if (handler == NULL) {
        spinlock_unlock(&ctx->spinlock);
        DIAG_ERROR("register handler is null.\n");
        return NULL;
    }

    spinlock_unlock(&ctx->spinlock);
    return handler;
}

