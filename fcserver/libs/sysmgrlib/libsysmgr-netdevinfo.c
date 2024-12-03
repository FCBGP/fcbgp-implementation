#include "libsysmgr.h"

#define SYS_PROC_PATH_NET_DEV SYS_PROC_PATH "net/dev"
#define PROC_NETDEV_FMT "%llu%llu%lu%lu%lu%lu%lu%lu%llu%llu%lu%lu%lu%lu%lu%lu"

/*
 * Inter-|   Receive                                                |  Transmit
 *  face |bytes    packets errs drop fifo frame compressed multicast|bytes
 * packets errs drop fifo colls carrier compressed lo:    7440      96    0    0
 * 0     0          0         0     7440      96    0    0    0     0       0 0
 *   p4p1: 1369039   16254    0    0    0     0          0         0      662 9
 * 0    0    0     0       0          0
 */

int sys_netdevinfo_get(sys_netdevinfo_t** pnetdevinfos)
{
    int cnt = 0;
    FILE* fp = NULL;
    char buf[256] = {
        0,
    };

    sys_netdevinfo_t* tail = NULL;
    sys_netdevinfo_t* head = NULL;
    sys_netdevinfo_t* netdevinfo = NULL;

    fp = fopen(SYS_PROC_PATH_NET_DEV, "r");
    if (fp == NULL)
    {
        return -ENOENT;
    }

    /* Skip headers */
    fgets(buf, sizeof(buf), fp);
    fgets(buf, sizeof(buf), fp);

    while (fgets(buf, sizeof(buf), fp))
    {
        int n = 0;
        char* p = buf;
        char* q = NULL;

        netdevinfo = calloc(1, sizeof(sys_netdevinfo_t));
        if (!netdevinfo)
        {
            return -ENOMEM;
        }

        q = netdevinfo->name;

        while (*p && *p != ':')
        {
            if (isspace((int)*p))
            {
                p++;
                continue;
            }

            *q++ = *p++;
            n++;
            if (n >= sizeof(netdevinfo->name))
            {
                *q = '\0';
                while (*(++p) != ':')
                    ;
                break;
            }
        }
        *q = '\0';
        p++;

        if (sscanf(p, PROC_NETDEV_FMT, &netdevinfo->rx_bytes,
                   &netdevinfo->rx_packets, &netdevinfo->rx_errors,
                   &netdevinfo->rx_dropped, &netdevinfo->rx_fifo_errors,
                   &netdevinfo->rx_frame_errors, &netdevinfo->rx_compressed,
                   &netdevinfo->rx_multicast, &netdevinfo->tx_bytes,
                   &netdevinfo->tx_packets, &netdevinfo->tx_errors,
                   &netdevinfo->tx_dropped, &netdevinfo->tx_fifo_errors,
                   &netdevinfo->collisions, &netdevinfo->tx_carrier_errors,
                   &netdevinfo->tx_compressed) != 16)
        {
            free(netdevinfo);
            continue;
        }

        if (tail)
        {
            tail->next = netdevinfo;
            tail = netdevinfo;
        }
        else
        {
            head = netdevinfo;
            tail = netdevinfo;
        }

        cnt++;
    }

    *pnetdevinfos = head;
    fclose(fp);
    return cnt;
}

int sys_netdevinfo_free(sys_netdevinfo_t* netdevinfos)
{
    sys_netdevinfo_t* cur = NULL;
    sys_netdevinfo_t* next = NULL;

    if (netdevinfos == NULL)
    {
        return 0;
    }

    cur = netdevinfos;
    while (cur)
    {
        next = cur->next;
        free(cur);
        cur = next;
    }

    return 0;
}
