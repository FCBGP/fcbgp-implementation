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
#include <signal.h>
#include <pthread.h>

#include "common.h"
#include "ds_asn_ip.h"
#include "dbutils.h"
#include "utils.h"
#include "libncs.h"
#include "libdiag.h"
#include "libhtable.h"

fcserver_t g_fcserver = {0};

void signal_handler(int sig_num)
{
    if (sig_num == SIGINT)
    {
        if (bgpd_ctx)
        {
            ncs_manager_stop(bgpd_ctx);
            ncs_destroy(bgpd_ctx);
            bgpd_ctx = NULL;
        }
        /*
        if (bc_ctx)
        {
            ncs_manager_stop(bc_ctx);
            ncs_destroy(bc_ctx);
            bc_ctx = NULL;
        }
        */
        fcserver_destroy();
        printf("bye bye!\n");
        exit(0);
    }
}

int fcserver_create()
{
    node_as_t meta;
    ht_node_as_t *node;

    init_db(&g_fcserver.db);

    meta.asn = g_fcserver.local_asn;
    node = htbl_meta_find(&g_fcserver.ht, &meta);

    if (node)
    {
        printf("asn: %d\n", node->asn);
        printf("  acs:\n");
        printf("    ipv4: %s\n", node->ap.acs.ipv4);
        printf("    ipv6: %s\n", node->ap.acs.ipv6);

        bgpd_server_create(&node->ap.acs);
        // broadcast_server_create(&node->ap.acs);
    }

    return 0;
}

int fcserver_destroy()
{
    printf("Close db\n");
    db_close(g_fcserver.db);
    printf("Destroy Hashtable\n");
    fcserver_hashtable_destroy(&g_fcserver.ht);
    printf("Close diag\n");
    diag_fini();

    return 0;
}
