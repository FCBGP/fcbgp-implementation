/********************************************************************************
* File Name:    bc_server_utils.c
* Author:       basilguo@163.com
* Created Time: 2023-09-28 07:37:37
* Description:
********************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sqlite3.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <signal.h>
#include <pthread.h>

#include "ds_binding_message.h"
#include "utils.h"
#include "libncs.h"
#include "libdiag.h"
#include "libhtable.h"

ncs_ctx_t *bc_ctx = NULL;

int broadcast_server_handler(ncs_ctx_t *ctx)
{
    int len = 0;
    char buff[BUFSIZ];
    do
    {
        memset(buff, 0, BUFSIZ);
        len = ncs_server_recv(ctx, buff, BUFSIZ);
        DIAG_DEBUG("received from %s:%d %s:%d %s:%s, len = %d\n",
                ctx->remote_addr, ctx->remote_port,
                ctx->local_addr, ctx->local_port,
                ctx->server_peeraddr, ctx->client_peeraddr, len);
        if (len > 0)
        {
            if (buff[0] == 2) // bm
            {
                bm_handler(buff, len, 1);
            } else {
                DIAG_ERROR("Not supported %d\n", buff[0]);
                continue;
            }
        }

    } while (1);

    ncs_client_stop(ctx);
    return 0;
}

void *broadcast_server_create(void *args)
{
    (void) args;
    if ((bc_ctx = ncs_create("broadcast", TCP_PROTO)) == NULL)
    {
        DIAG_ERROR("create broadcast ncs failed\n");
        exit(-ENOMEM);
    }

    ncs_setup(bc_ctx, INADDR_ANY, FC_BROADCAST_PORT, NULL, 0);
    ncs_timeout(bc_ctx, 10, -1);
    ncs_setkeepalive(bc_ctx, 10);
    ncs_server_enable(bc_ctx);
    ncs_server_register(bc_ctx, broadcast_server_handler);
    ncs_manager_start(bc_ctx);

    return NULL;
}
