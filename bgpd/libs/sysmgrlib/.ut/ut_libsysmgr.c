#include "libsysmgr.h"

int ut_arpinfo(void)
{
    sys_arpinfo_t *arpinfo;
    sys_arpinfo_t *arpinfos = NULL;

    printf("\n=====arp info====\n");
    sys_arpinfo_get(&arpinfos);

    arpinfo = arpinfos;
    while (arpinfo) {
        printf("%s 0x%x 0x%x %02x:%02x:%02x:%02x:%02x:%02x %s %s\n",
            arpinfo->ipaddr, arpinfo->hwtype, arpinfo->flags,
            arpinfo->hwaddr[0], arpinfo->hwaddr[1], arpinfo->hwaddr[2], arpinfo->hwaddr[3],
            arpinfo->hwaddr[4], arpinfo->hwaddr[5], arpinfo->mask, arpinfo->ifname);
        arpinfo = arpinfo->next;
    }

    sys_arpinfo_free(arpinfos);
    return 0;
}

int ut_cpuinfo(void)
{
    sys_cpuinfo_t *cpuinfo;
    sys_cpuinfo_t *cpuinfos = NULL;

    printf("\n=====cpu info====\n");
    sys_cpuinfo_get(&cpuinfos);

    cpuinfo = cpuinfos;
    while (cpuinfo) {
        printf("name %s user %u nice %u system %u idle %u iowait %u irq %u softirq %u\n",
            cpuinfo->name, cpuinfo->user, cpuinfo->nice, cpuinfo->system, cpuinfo->idle, cpuinfo->iowait, cpuinfo->irq, cpuinfo->softirq);
        cpuinfo = cpuinfo->next;
    }

    sys_cpuinfo_free(cpuinfos);
    return 0;
}

int ut_diskinfo(void)
{
    sys_diskinfo_t *diskinfo;
    sys_diskinfo_t *diskinfos = NULL;

    printf("\n=====disk info====\n");
    sys_diskinfo_get(&diskinfos);

    diskinfo = diskinfos;
    while (diskinfo) {
        printf("%s %lu %lu %lu %d %s\n", diskinfo->filesystem, diskinfo->blocks, diskinfo->used,
                diskinfo->available, diskinfo->usage_rate, diskinfo->mounted_on);
        diskinfo = diskinfo->next;
    }

    sys_diskinfo_free(diskinfos);
    return 0;
}

int ut_netdevinfo(void)
{
    sys_netdevinfo_t *netdevinfo;
    sys_netdevinfo_t *netdevinfos = NULL;

    printf("\n=====netdev info====\n");
    sys_netdevinfo_get(&netdevinfos);

    netdevinfo = netdevinfos;
    while (netdevinfo) {
        printf("%s %llu %llu %lu %lu %lu %lu %lu %lu %llu %llu %lu %lu %lu %lu %lu %lu \n",
                netdevinfo->name, netdevinfo->rx_bytes, netdevinfo->rx_packets, netdevinfo->rx_errors,
            netdevinfo->rx_dropped, netdevinfo->rx_fifo_errors, netdevinfo->rx_frame_errors, netdevinfo->rx_compressed,
            netdevinfo->rx_multicast, netdevinfo->tx_bytes, netdevinfo->tx_packets, netdevinfo->tx_errors, netdevinfo->tx_dropped,
            netdevinfo->tx_fifo_errors, netdevinfo->collisions, netdevinfo->tx_carrier_errors, netdevinfo->tx_compressed);
        netdevinfo = netdevinfo->next;
    }

    sys_netdevinfo_free(netdevinfos);
    return 0;
}

int ut_pidinfo(void)
{
    sys_pidinfo_t *pidinfo;
    sys_pidinfo_t *pidinfos = NULL;

    printf("\n=====pid info====\n");
    sys_pidinfo_gets(&pidinfos);

    pidinfo = pidinfos;
    while (pidinfo) {
        printf("name %s pid %d state %c memrss %ld mem_shared %ld time %lld "
                "time_s %ld pcpu %d priority %ld nice %ld sched %d sched_str %s\n",
            pidinfo->name, pidinfo->pid, pidinfo->state, pidinfo->mem_rss, pidinfo->mem_shared, pidinfo->time, pidinfo->time_s, pidinfo->pcpu,
            pidinfo->priority, pidinfo->nice, pidinfo->sched, pidinfo->sched_str);
        pidinfo = pidinfo->next;
    }

    sys_pidinfo_free(pidinfos);
    return 0;
}

int ut_routeinfo(void)
{
    sys_routeinfo_t *routeinfo;
    sys_routeinfo_t *routeinfos = NULL;

    printf("\n=====route info====\n");
    sys_routeinfo_get(&routeinfos, 0xFFFF);

    routeinfo = routeinfos;
    while (routeinfo) {
        printf("%s %lu %lu %lu %d %d %d %d %d %d %d\n", routeinfo->ifname, routeinfo->rt_ldest, routeinfo->rt_lgway, routeinfo->rt_lmask,
            routeinfo->rt_flags, routeinfo->rt_ref, routeinfo->rt_use, routeinfo->rt_metric, routeinfo->rt_mtu, routeinfo->rt_window, routeinfo->rt_irtt);
        routeinfo = routeinfo->next;
    }

    sys_routeinfo_free(routeinfos);
    return 0;
}

int ut_bootver(int argc, char *argv[])
{
    mbs_t bootver = NULL;

    bootver = sys_bootver_get(argv[1], argv[2]);

    printf("get boot ver [%s]\n", bootver);
    mbsfree(bootver);
    return 0;
}

int main(int argc, char *argv[])
{
    ut_arpinfo();
    ut_cpuinfo();
    ut_diskinfo();
    ut_netdevinfo();
    ut_pidinfo();
    ut_routeinfo();

    char *datetime = sys_datetime_get();
    if (datetime) {
        printf("datetime=[%s]\n", datetime);
        free(datetime);
    }

    ut_bootver(argc, argv);
    return 0;
}
