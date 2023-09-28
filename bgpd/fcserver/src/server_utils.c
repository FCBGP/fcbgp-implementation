/********************************************************************************
* File Name:    server_utils.c
* Author:       basilguo@163.com
* Created Time: 2023-09-28 07:37:37
* Description:
********************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <sqlite3.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "utils.h"
#include "libncs.h"
#include "libdiag.h"
#include "libhtable.h"

fcserver_t g_fcserver;

int fcserver_create()
{
    memset(&g_fcserver, 0, sizeof(fcserver_t));
    return 0;
}

int fcserver_destroy()
{
    fcserver_hashtable_destroy(&g_fcserver.ht);
    return 0;
}

static int broadcast_server_handler(ncs_ctx_t *ctx)
{
    ncs_client_stop(ctx);
    return 0;
}

int broadcast_server_create()
{
    ncs_ctx_t *bc_ctx = NULL;
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

    ncs_destroy(bc_ctx);
    return 0;
}

static int bgpd_server_handler(ncs_ctx_t *ctx)
{
    ncs_client_stop(ctx);

    return 0;
}

int bgpd_server_create()
{
    ncs_ctx_t *bgpd_ctx = NULL;
    if ((bgpd_ctx = ncs_create("bgpd", TCP_PROTO)) == NULL)
    {
        DIAG_ERROR("create bgpd ncs failed\n");
        exit(-ENOMEM);
    }

    ncs_setup(bgpd_ctx, INADDR_ANY, FC_BGPD_PORT, NULL, 0);
    ncs_timeout(bgpd_ctx, 10, -1);
    ncs_setkeepalive(bgpd_ctx, 10);
    ncs_server_enable(bgpd_ctx);
    ncs_server_register(bgpd_ctx, bgpd_server_handler);
    ncs_manager_start(bgpd_ctx);

    ncs_destroy(bgpd_ctx);

    return 0;
}
