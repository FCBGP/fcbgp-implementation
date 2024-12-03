#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include "libdiag.h"
#include "liblist.h"
#include "libnio.h"

/*
 * libnio - the network I/O library
 */

nio_ctx_t* nio_create(char* ifname, uint8_t* smac, uint8_t* dmac,
                      struct nio_ops_st* ops)
{
    nio_ctx_t* ctx = malloc(sizeof(struct nio_ctx_st));
    if (ctx == NULL)
        return NULL;

    memset(ctx, 0, sizeof(struct nio_ctx_st));

    ctx->ifname = ifname;
    memcpy(ctx->smac, smac, 6);
    memcpy(ctx->dmac, dmac, 6);
    INIT_LIST_HEAD(&ctx->ptype_head);

    ctx->verbose = 0;
    ctx->ops = ops;
    return ctx;
}

static void* nio_listen(void* arg)
{
    int ret;
    int droped = 0;
    nio_pkt_t pkt;
    nio_ctx_t* ctx = arg;
    struct nio_ptype_st* ptype;

    ctx->running = 1;

    while (1)
    {
        if (!ctx->running)
            break;

        if (ctx->ops == NULL || ctx->ops->recv == NULL)
            continue;

        ret = ctx->ops->recv(ctx, &pkt);
        if (ret < 0)
            continue;

        ctx->rx_packets++;
        ctx->rx_bytes += pkt.length;

        if (ctx->verbose)
        {
            DIAG_MEMORY(pkt.data, pkt.length,
                        "nio %s recv the %uth packet %d/%u bytes\n",
                        ctx->ifname, ctx->rx_packets, pkt.length,
                        ctx->rx_bytes);
        }

        droped = 0;
        list_for_each_entry(ptype, &ctx->ptype_head, ptype_node)
        {
            if (ptype->proto == pkt.proto && ptype->handler)
            {
                ret = ptype->handler(ctx, &pkt);
                if (ret < 0)
                {
                    if (ctx->ops->drop)
                    {
                        ctx->ops->drop(ctx, &pkt);
                    }
                }
                droped = 1;
                break;
            }
        }

        if (!droped)
        {
            if (ctx->ops->drop)
            {
                ctx->ops->drop(ctx, &pkt);
            }
        }
    }

    ctx->running = 0;
    pthread_exit((void*)0);
    return NULL;
}

int nio_start(nio_ctx_t* ctx)
{
    int i = 0;
    int ret = -1;

    if (ctx->running)
    {
        DIAG_ERROR("nio already started.\n");
        return -EBUSY;
    }

    ret = pthread_create(&ctx->pid, NULL, nio_listen, (void*)ctx);
    if (ret != 0)
    {
        DIAG_ERROR("create thread failed: %d\n", ret);
        return -ECHILD;
    }

    // waiting for the thread is running.
    while (i < 10000)
    {
        if (ctx->running)
        {
            DIAG_INFO("nio %s started.\n", ctx->ifname);
            return 0;
        }
        usleep(1000);
        i++;
    }

    return -ENOEXEC;
}

void nio_stop(nio_ctx_t* ctx)
{
    if (ctx)
    {
        if (ctx->running)
        {
            ctx->running = 0;
            pthread_join(ctx->pid, NULL);
            DIAG_INFO("nio %s stoped.\n", ctx->ifname);
        }
    }

    return;
}

int nio_send(nio_ctx_t* ctx, uint16_t proto, uint8_t* data, int len)
{
    if (ctx == NULL || ctx->ops == NULL || ctx->ops->send == NULL)
        return -EINVAL;

    ctx->tx_packets++;
    ctx->tx_bytes += len;

    if (ctx->verbose)
    {
        DIAG_MEMORY(data, len, "nio %s send the %uth packet %d/%u bytes\n",
                    ctx->ifname, ctx->tx_packets, len, ctx->tx_bytes);
    }

    return ctx->ops->send(ctx, proto, data, len);
}

int nio_forward(nio_ctx_t* ctx, uint16_t proto, nio_pkt_t* pkt)
{
    if (ctx == NULL || ctx->ops == NULL || ctx->ops->forward == NULL)
        return -EINVAL;

    return ctx->ops->forward(ctx, proto, pkt);
}

int nio_forward6(nio_ctx_t* ctx, uint16_t proto, nio_pkt_t* pkt)
{
    if (ctx == NULL || ctx->ops == NULL || ctx->ops->forward == NULL)
        return -EINVAL;

    return ctx->ops->forward6(ctx, proto, pkt);
}

int nio_drop(nio_ctx_t* ctx, nio_pkt_t* pkt)
{
    if (ctx == NULL || ctx->ops == NULL || ctx->ops->drop == NULL)
        return -EINVAL;

    return ctx->ops->drop(ctx, pkt);
}

int nio_add_ptype(nio_ctx_t* ctx, uint16_t proto,
                  int (*handler)(nio_ctx_t* ctx, nio_pkt_t* pkt))
{
    struct nio_ptype_st* ptype;

    ptype = malloc(sizeof(struct nio_ptype_st));
    if (ptype == NULL)
        return -ENOMEM;

    ptype->proto = proto;
    ptype->handler = handler;
    my_list_add(&ptype->ptype_node, &ctx->ptype_head);

    return 0;
}

int nio_open(nio_ctx_t* ctx, int argc, int* argv)
{
    if (ctx->ops == NULL || ctx->ops->open == NULL)
        return -EINVAL;

    return ctx->ops->open(ctx, argc, argv);
}

void nio_close(nio_ctx_t* ctx)
{
    struct nio_ptype_st* ptype;
    struct nio_ptype_st* tmp_ptype;

    if (ctx)
    {
        list_for_each_entry_safe(ptype, tmp_ptype, &ctx->ptype_head, ptype_node)
        {
            list_del(&ptype->ptype_node);
            free(ptype);
        }

        if (ctx->ops)
        {
            if (ctx->ops->close)
            {
                ctx->ops->close(ctx);
            }
        }

        free(ctx);
    }
}

int nio_verbose(nio_ctx_t* ctx, int verbose)
{
    if (ctx == NULL)
    {
        return 0;
    }

    int old_verbose = ctx->verbose;

    if (verbose == 1 || verbose == 0)
    {
        ctx->verbose = verbose;
    }

    return old_verbose;
}
