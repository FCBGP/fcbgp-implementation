#include "libsysmgr.h"

#define SYS_PROC_PATH_NET_ROUTE SYS_PROC_PATH "net/route"
#define PROC_NETROUTE_FMT "%s %s %s %d %d %d %d %s %d %d %d"

/*
 * Iface   Destination Gateway     Flags   RefCnt  Use Metric  Mask        MTU
 * Window  IRTT p4p1    000114AC    00000000    0001    0   0   1   00FFFFFF 0
 * 0   0 p4p1    004D000A    00000000    0001    0   0   0   00FFFFFF    0   0 0
 *  p4p1    00000000    FE4D000A    0003    0   0   0   00000000    0   0   0
 */

int sys_routeinfo_get(sys_routeinfo_t** prouteinfos, int flags)
{
    int cnt = 0;
    FILE* fp = NULL;
    char buf[256] = {
        0,
    };

    sys_routeinfo_t* tail = NULL;
    sys_routeinfo_t* head = NULL;
    sys_routeinfo_t* routeinfo = NULL;

    fp = fopen(SYS_PROC_PATH_NET_ROUTE, "r");
    if (fp == NULL)
    {
        return -ENOENT;
    }

    /* Skip header */
    fgets(buf, sizeof(buf), fp);

    while (fgets(buf, sizeof(buf), fp))
    {
        char dest[16], gway[16], mask[16];

        routeinfo = calloc(1, sizeof(sys_routeinfo_t));
        if (routeinfo == NULL)
        {
            return -ENOMEM;
        }

        if (sscanf(buf, PROC_NETROUTE_FMT, routeinfo->ifname, dest, gway,
                   &routeinfo->rt_flags, &routeinfo->rt_ref, &routeinfo->rt_use,
                   &routeinfo->rt_metric, mask, &routeinfo->rt_mtu,
                   &routeinfo->rt_window, &routeinfo->rt_irtt) != 11)
        {
            free(routeinfo);
            continue;
        }

        if ((routeinfo->rt_flags & flags) == 0)
        {
            free(routeinfo);
            continue;
        }

        routeinfo->rt_ldest = parse_hex32(dest);
        routeinfo->rt_lmask = parse_hex32(mask);
        routeinfo->rt_lgway = parse_hex32(gway);

        if (tail)
        {
            tail->next = routeinfo;
            tail = routeinfo;
        }
        else
        {
            head = routeinfo;
            tail = routeinfo;
        }

        cnt++;
    }

    *prouteinfos = head;
    fclose(fp);
    return cnt;
}

int sys_routeinfo_free(sys_routeinfo_t* routeinfos)
{
    sys_routeinfo_t* cur = NULL;
    sys_routeinfo_t* next = NULL;

    if (routeinfos == NULL)
    {
        return 0;
    }

    cur = routeinfos;
    while (cur)
    {
        next = cur->next;
        free(cur);
        cur = next;
    }

    return 0;
}
