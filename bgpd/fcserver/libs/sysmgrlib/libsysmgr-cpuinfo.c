#include "libsysmgr.h"

#define SYS_PROC_PATH_STAT SYS_PROC_PATH "stat"

/*
 * cpu  55652 153 23710 36760632 22188 76 75 0 0
 * cpu0 19680 36 8903 9172870 11731 62 49 0 0
 * cpu1 10787 57 7264 9190293 8007 14 18 0 0
 * cpu2 17899 28 4971 9191934 1518 0 6 0 0
 * cpu3 7285 31 2572 9205533 931 0 1 0 0
 */
int sys_cpuinfo_get(sys_cpuinfo_t ** pcpuinfos)
{
    int cnt = 0;
    FILE *fp = NULL;
    char buf[256] = { 0, };

    sys_cpuinfo_t *tail = NULL;
    sys_cpuinfo_t *head = NULL;
    sys_cpuinfo_t *cpuinfo = NULL;

    fp = fopen(SYS_PROC_PATH_STAT, "r");
    if (fp == NULL) {
        return -ENOENT;
    }

    /* Skip header */
    fgets(buf, sizeof(buf), fp);

    while (fgets(buf, sizeof(buf), fp)) {
        cpuinfo = calloc(1, sizeof(sys_cpuinfo_t));
        if (cpuinfo == NULL) {
            return -ENOMEM;
        }

        if (sscanf(buf, "%s %u %u %u %u %u %u %u", cpuinfo->name, &cpuinfo->user, &cpuinfo->nice, &cpuinfo->system,
                    &cpuinfo->idle, &cpuinfo->iowait, &cpuinfo->irq, &cpuinfo->softirq) != 8) {
            free(cpuinfo);
            continue;
        }

        if (strncmp(cpuinfo->name, "cpu", 3)) {
            free(cpuinfo);
            continue;
        }

        cpuinfo->total = cpuinfo->user + cpuinfo->nice + cpuinfo->system + cpuinfo->idle + cpuinfo->iowait + cpuinfo->irq + cpuinfo->softirq;

        cpuinfo->next = NULL;
        if (tail) {
            tail->next = cpuinfo;
            tail = cpuinfo;
        } else {
            head = cpuinfo;
            tail = cpuinfo;
        }

        cnt++;
    }

    *pcpuinfos = head;
    fclose(fp);
    return cnt;
}

int sys_cpuinfo_free(sys_cpuinfo_t *cpuinfos)
{
    sys_cpuinfo_t *cur = NULL;
    sys_cpuinfo_t *next = NULL;

    if (cpuinfos == NULL) {
        return 0;
    }

    cur = cpuinfos;
    while (cur) {
        next = cur->next;
        free(cur);
        cur = next;
    }

    return 0;
}

