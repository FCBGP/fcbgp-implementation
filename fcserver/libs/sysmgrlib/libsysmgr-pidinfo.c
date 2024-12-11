#include "libsysmgr.h"

#define LINEBUFF_SZ 256
#define HZ 1000

#define SCHED_NONE_STR "none"
#define SCHED_NICE_STR "nice"
#define SCHED_FIFO_STR "fifo"
#define SCHED_RR_STR "round robin"

#define PARSE_PROC_STATM "%*s %lu %lu"
#define PARSE_PROC_UPTIME "%lu.%lu"
#define PARSE_PROC_STAT                                                        \
    "%c %*d %*d %*d %*d %*d %*u %*u %*u "                                      \
    "%*u %*u %lu %lu %*d %*d %ld %ld %*d %*d %lu"

static int sys_pidinfo_get(int pid, sys_pidinfo_t* pidinfo)
{
    int ret = -1;
    FILE* fp = NULL;
    unsigned long utime = 0;
    unsigned long stime = 0;
    unsigned long starttime = 0;
    unsigned long long uptime = 0;
    char procfile[LINEBUFF_SZ + 1];
    char buffer[512] = {};
    char* ptr1 = buffer;
    char* ptr2 = pidinfo->name;

    if (pid <= 0 || !pidinfo)
        goto proc_info_exit;

    memset(procfile, 0, LINEBUFF_SZ + 1);
    pidinfo->sched = sched_getscheduler(pid);
    pidinfo->pid = pid;

    snprintf(procfile, LINEBUFF_SZ, "/proc/%d/statm", pid);
    if (!(fp = fopen(procfile, "r")))
        goto proc_info_exit;

    if (fscanf(fp, PARSE_PROC_STATM, &pidinfo->mem_rss, &pidinfo->mem_shared) !=
        2)
        goto proc_info_exit;

    fclose(fp);

    if (!(fp = fopen("/proc/uptime", "r")))
        goto proc_info_exit;

    if (fscanf(fp, PARSE_PROC_UPTIME, &stime, &utime) != 2)
        goto proc_info_exit;

    uptime = (stime * 100) + utime;
    fclose(fp);

    snprintf(procfile, LINEBUFF_SZ, "/proc/%d/stat", pid);
    if (!(fp = fopen(procfile, "r")))
        goto proc_info_exit;

    if (fread(buffer, sizeof(char), sizeof(buffer), fp) <= 0)
        goto proc_info_exit;
    fclose(fp);
    fp = NULL;

    while (*ptr1 && *ptr1++ != '(')
        /* skip */;

    while (*ptr1 && *ptr1 != ')')
        *ptr2++ = *ptr1++;
    *ptr2 = '\0';
    ptr1 += 2;

    if (sscanf(ptr1, PARSE_PROC_STAT, &pidinfo->state, &utime, &stime,
               &pidinfo->priority, &pidinfo->nice, &starttime) != 6)
        goto proc_info_exit;

    pidinfo->time = (stime + utime);      // in jiffies
    pidinfo->pcpu = (uptime - starttime); // in jiffies
    pidinfo->pcpu = pidinfo->pcpu > pidinfo->time
                        ? (int)(((double)(pidinfo->time) * 100) / pidinfo->pcpu)
                        : 0;

    pidinfo->time_s = (pidinfo->time % HZ);
    pidinfo->time = (pidinfo->time / HZ);

    switch (pidinfo->sched)
    {
        case SCHED_OTHER:
            pidinfo->sched_str = SCHED_NICE_STR; /* Std UNIX scheduler */
            break;
        case SCHED_FIFO:
            pidinfo->sched_str = SCHED_FIFO_STR; /* FIFO scheduler */
            break;

        case SCHED_RR:
            pidinfo->sched_str = SCHED_RR_STR; /* Round Robin scheduler */
            break;

        default:
            pidinfo->sched_str = SCHED_NONE_STR; /* Undefined scheduler */
            break;
    }

    ret = 0;

proc_info_exit:
    if (fp)
        fclose(fp);

    return ret;
}

int sys_pidinfo_gets(sys_pidinfo_t** ppidinfos)
{
    int cnt = 0;
    DIR* d = NULL;
    struct dirent* pd = NULL;

    sys_pidinfo_t* tail = NULL;
    sys_pidinfo_t* head = NULL;
    sys_pidinfo_t* pidinfo = NULL;

    d = opendir(SYS_PROC_PATH);
    if (d == NULL)
    {
        return -ENOENT;
    }

    while ((pd = readdir(d)) != 0)
    {
        pidinfo = calloc(1, sizeof(sys_pidinfo_t));
        if (!pidinfo)
        {
            return -ENOMEM;
        }

        /* Skip uninteresting files */
        if (!isdigit((int)(pd->d_name[0])))
        {
            free(pidinfo);
            continue;
        }

        if (sys_pidinfo_get(atoi(pd->d_name), pidinfo) != 0)
        {
            free(pidinfo);
            continue;
        }

        if (tail)
        {
            tail->next = pidinfo;
            tail = pidinfo;
        }
        else
        {
            head = pidinfo;
            tail = pidinfo;
        }

        cnt++;
    }

    *ppidinfos = head;
    closedir(d);
    return cnt;
}

int sys_pidinfo_free(sys_pidinfo_t* pidinfos)
{
    sys_pidinfo_t* cur = NULL;
    sys_pidinfo_t* next = NULL;

    if (pidinfos == NULL)
    {
        return 0;
    }

    cur = pidinfos;
    while (cur)
    {
        next = cur->next;
        free(cur);
        cur = next;
    }

    return 0;
}

int sys_check_process(char* appname)
{
    sys_pidinfo_t* pidinfo = NULL;
    sys_pidinfo_t* pidinfos = NULL;

    int pidcnt = sys_pidinfo_gets(&pidinfos);
    if (pidcnt < 0)
    {
        return 0;
    }

    pidinfo = pidinfos;
    while (pidinfo)
    {
        if (strcmp(pidinfo->name, appname) == 0)
        {
            if (pidinfo->pid != getpid())
            {
                fprintf(stderr, "process %s has been exist as pid %d\n",
                        appname, pidinfo->pid);
                sys_pidinfo_free(pidinfos);
                return 1;
            }
        }

        pidinfo = pidinfo->next;
    }

    sys_pidinfo_free(pidinfos);
    return 0;
}
