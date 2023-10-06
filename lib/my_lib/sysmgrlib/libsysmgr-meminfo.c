#include <stdlib.h>
#include "libsysmgr.h"

#define SYS_PROC_PATH_MEM_ROUTE SYS_PROC_PATH "meminfo"
#define PROC_MEMINFO_FMT "%s %s %s"

/*
 * MemTotal:        3822568 kB
 * MemFree:         3206564 kB
 * Buffers:           32376 kB
 * Cached:           256352 kB
 */

int sys_meminfo_get(sys_meminfo_t **pmeminfo)
{
    int i;
    FILE *fp = NULL;
    char buf[256] = {0, };
    char name[16] = {0, };
    char size[16] = {0, };
    char symb[16] = {0, };
    int values[4] = { 0, };

    sys_meminfo_t *meminfo = malloc(sizeof(sys_meminfo_t));
    if (meminfo == NULL) {
        return -ENOMEM;
    }

    fp = fopen(SYS_PROC_PATH_MEM_ROUTE, "r");
    if (fp == NULL) {
        free(meminfo);
        return -ENOENT;
    }

    for (i = 0; i < 4; i++) {
        fgets(buf, sizeof(buf), fp);

        if (sscanf(buf, PROC_MEMINFO_FMT, name, size, symb) != 3) {
            free(meminfo);
            return -EINVAL;
        }

        values[i] = atoi(size);
    }

    meminfo->total = values[0] / 1024;
    meminfo->used = (values[0] - (values[1] + values[2] + values[3])) / 1024;
    meminfo->available = (values[1] + values[2] + values[3]) / 1024;
    fclose(fp);

    *pmeminfo = meminfo;
    return 0;
}

int sys_meminfo_free(sys_meminfo_t *meminfo)
{
    if (meminfo) {
        free(meminfo);
    }

    return 0;
}
