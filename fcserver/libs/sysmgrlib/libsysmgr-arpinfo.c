#include "libsysmgr.h"

#define SYS_PROC_PATH_NET_ARP SYS_PROC_PATH "net/arp"
#define PROC_NET_ARP_FMT "%s 0x%x 0x%x %02x:%02x:%02x:%02x:%02x:%02x %s %s"

/*
 * IP address       HW type     Flags       HW address            Mask     Device
 * 10.168.7.126     0x1         0x2         00:08:74:E6:64:BB     *        eth2
 * 10.64.64.6       0x1         0x2         00:02:2D:6D:9D:DA     *        eth1
 * 10.64.64.100     0x1         0x2         00:50:2C:05:BA:E8     *        eth1
 * 24.18.32.1       0x1         0x2         00:01:5C:22:8A:02     *        eth0
 */
int sys_arpinfo_get(sys_arpinfo_t ** parpinfos)
{
    int cnt = 0;
    FILE *fp = NULL;
    char buf[256] = { 0, };

    sys_arpinfo_t *tail = NULL;
    sys_arpinfo_t *head = NULL;
    sys_arpinfo_t *arpinfo = NULL;

    fp = fopen(SYS_PROC_PATH_NET_ARP, "r");
    if (fp == NULL) {
        fprintf(stderr, "open %s failed.\n", SYS_PROC_PATH_NET_ARP);
        return -ENOENT;
    }

    /* Skip header */
    fgets(buf, sizeof(buf), fp);

    while (fgets(buf, sizeof(buf), fp)) {
        arpinfo = calloc(1, sizeof(sys_arpinfo_t));
        if (arpinfo == NULL) {
            return -ENOMEM;
        }

        if (sscanf(buf, PROC_NET_ARP_FMT, arpinfo->ipaddr, &arpinfo->hwtype, &arpinfo->flags,
                &arpinfo->hwaddr[0], &arpinfo->hwaddr[1], &arpinfo->hwaddr[2], &arpinfo->hwaddr[3],
                &arpinfo->hwaddr[4], &arpinfo->hwaddr[5], arpinfo->mask, arpinfo->ifname) != 11) {
            free(arpinfo);
            continue;
        }

        arpinfo->next = NULL;
        if (tail) {
            tail->next = arpinfo;
            tail = arpinfo;
        } else {
            head = arpinfo;
            tail = arpinfo;
        }

        cnt++;
    }

    *parpinfos = head;
    fclose(fp);
    return cnt;
}

int sys_arpinfo_free(sys_arpinfo_t *arpinfos)
{
    sys_arpinfo_t *cur = NULL;
    sys_arpinfo_t *next = NULL;

    if (arpinfos == NULL) {
        return 0;
    }

    cur = arpinfos;
    while (cur) {
        next = cur->next;
        free(cur);
        cur = next;
    }

    return 0;
}

