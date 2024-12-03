#include "libsysmgr.h"
#include "libdiag.h"
#include "libendian.h"
#include "libstring.h"

#include <fcntl.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>

int sys_temperature_get(void)
{
    int temp = 0;

#ifndef __host__
    char* tempinfo = NULL;

    tempinfo = strappendstdout(
        &tempinfo, "cat /sys/class/hwmon/hwmon0/device/temp1_input");
    if (tempinfo)
    {
        sscanf(tempinfo, "%d", &temp);
        free(tempinfo);
    }
#endif

    return temp;
}

mbs_t sys_bootver_get(char* filename, char* pattern)
{
    int fd = -1;
    int rdlen = 0;
    int patlen = 0;
    int datalen = 34000;
    char* data = NULL;
    char* p = NULL;
    char* q = NULL;
    char* t = NULL;
    mbs_t bootver = NULL;

    fd = open(filename, O_RDONLY);
    if (fd < 0)
    {
        return mbscat(&bootver, "unknown");
    }

    data = malloc(datalen);
    if (data == NULL)
    {
        close(fd);
        return mbsnew("unknown");
    }

    rdlen = read(fd, data, datalen - 1);
    if (rdlen <= 0)
    {
        close(fd);
        free(data);
        return mbsnew("unknown");
    }

    data[rdlen] = '\0';

    p = data;
    t = data + rdlen - 1;
    patlen = strlen(pattern);

    while (p + patlen < t)
    {
        if (memcmp(p, pattern, patlen))
        {
            p++;
            continue;
        }

        q = p;
        while (q < t)
        {
            if (isprint(*q))
            {
                mbscatchar(&bootver, *q);
                q++;
            }
            else
            {
                break;
            }
        }
        break;
    }

    close(fd);
    free(data);
    return mbsrtrim(bootver, NULL);
}

mbs_t sys_linuxver_get(void)
{
    mbs_t linuxver = NULL;

    linuxver = mbscatstdout(&linuxver, "uname -r");
    if (linuxver == NULL)
    {
        linuxver = mbscat(&linuxver, "unknown");
    }

    return mbsrtrim(linuxver, NULL);
}

mbs_t sys_rootfsver_get(void)
{
    mbs_t rootfsver = NULL;

    rootfsver = mbscatstdout(&rootfsver, "cat /etc/version 2>/dev/null");
    if (rootfsver == NULL)
    {
        rootfsver = mbscat(&rootfsver, "unknown");
    }

    return mbsrtrim(rootfsver, NULL);
}

int sys_info_get(sys_info_t** psysinfo)
{
    int ret = -1;

    sys_info_t* info = malloc(sizeof(sys_info_t));
    if (info == NULL)
    {
        return -ENOMEM;
    }

    ret = uname(&info->uname);
    if (ret < 0)
    {
        free(info);
        return ret;
    }

    ret = sysinfo(&info->sysinfo);
    if (ret < 0)
    {
        free(info);
        return ret;
    }

    ret = sys_cpuinfo_get(&info->cpuinfo);
    if (ret < 0)
    {
        free(info);
        return ret;
    }
    info->cpu_cnt = ret;

    ret = sys_meminfo_get(&info->meminfo);
    if (ret < 0)
    {
        sys_cpuinfo_free(info->cpuinfo);
        free(info);
        return ret;
    }

    ret = sys_diskinfo_get(&info->diskinfo);
    if (ret < 0)
    {
        sys_meminfo_free(info->meminfo);
        sys_cpuinfo_free(info->cpuinfo);
        free(info);
        return ret;
    }

    info->disk_cnt = ret;
    info->time = time(NULL) + 1;
    info->cpu_endian = get_endian();
    info->cpu_width = sizeof(void*) * 8;
    info->cpu_pagesize = sysconf(_SC_PAGESIZE);
    info->cpu_temperature = sys_temperature_get();

    *psysinfo = info;
    return 0;
}

int sys_info_free(sys_info_t* sysinfo)
{
    if (sysinfo)
    {
        sys_diskinfo_free(sysinfo->diskinfo);
        sys_meminfo_free(sysinfo->meminfo);
        sys_cpuinfo_free(sysinfo->cpuinfo);
        free(sysinfo);
    }

    return 0;
}

char* sys_dmesg(void)
{
    char* dmesg = NULL;

    dmesg = strappendstdout(&dmesg, "dmesg | tail -n 300");
    if (dmesg == NULL)
    {
        return NULL;
    }

    return dmesg;
}

char* sys_ifconfig(void)
{
    char* ifinfo = NULL;

    ifinfo = strappendstdout(&ifinfo, "ifconfig -a");
    if (ifinfo == NULL)
    {
        return NULL;
    }

    return ifinfo;
}

static void* sys_reboot_handler(void* arg)
{
    sleep(10);
    system("reboot");
    return NULL;
}

int sys_reboot(void)
{
    pthread_t tid;

    if (pthread_create(&tid, NULL, (void*)sys_reboot_handler, NULL))
    {
        DIAG_ERROR("create reboot thread failed\n");
        return -ECHILD;
    }

    return 0;
}

static void* sys_poweroff_handler(void* arg)
{
    sleep(10);
    system("poweroff");
    return NULL;
}

int sys_poweroff(void)
{
    pthread_t tid;

    if (pthread_create(&tid, NULL, (void*)sys_poweroff_handler, NULL))
    {
        DIAG_ERROR("create poweroff thread failed\n");
        return -ECHILD;
    }

    return 0;
}

int sys_route_add(char* ipaddr_str, char* netmask_str, char* gwaddr_str)
{
    var_ipaddr4_t ipaddr;
    var_ipaddr4_t netmask;
    var_ipaddr4_t gwaddr;

    mbs_t cmdline = NULL;

    if (ipaddr_str == NULL || netmask_str == NULL || gwaddr_str == NULL)
        return -EINVAL;

    if (parse_ipaddr4(ipaddr_str, &ipaddr))
    {
        DIAG_ERROR("parse route add prefix address %s failed\n", ipaddr_str);
        return -EINVAL;
    }

    if (parse_ipaddr4(netmask_str, &netmask))
    {
        DIAG_ERROR("parse route add netmask %s failed\n", netmask_str);
        return -EINVAL;
    }

    mbscatfmt(&cmdline, "route add -net  \"%u.%u.%u.%u\" netmask ",
              ipaddr.u.addr8[0], ipaddr.u.addr8[1], ipaddr.u.addr8[2],
              ipaddr.u.addr8[3]);

    if (parse_ipaddr4(gwaddr_str, &gwaddr))
    {
        DIAG_ERROR("parse route add gateway address %s failed\n", gwaddr_str);
        return -EINVAL;
    }

    mbscatfmt(&cmdline, "%u.%u.%u.%u gw %u.%u.%u.%u", netmask.u.addr8[0],
              netmask.u.addr8[1], netmask.u.addr8[2], netmask.u.addr8[3],
              gwaddr.u.addr8[0], gwaddr.u.addr8[1], gwaddr.u.addr8[2],
              gwaddr.u.addr8[3]);

    if (system(cmdline))
    {
        mbsfree(cmdline);
        return -EINTR;
    }

    mbsfree(cmdline);
    return 0;
}

int sys_route_del(char* ipaddr_str, char* netmask_str)
{
    var_ipaddr4_t ipaddr;
    var_ipaddr4_t netmask;
    mbs_t cmdline = NULL;

    if (parse_ipaddr4(ipaddr_str, &ipaddr))
    {
        DIAG_ERROR("parse route del prefix address %s failed\n", ipaddr_str);
        return -EINVAL;
    }

    if (parse_ipaddr4(netmask_str, &netmask))
    {
        DIAG_ERROR("parse route del netmask %s failed\n", netmask_str);
        return -EINVAL;
    }

    mbscatfmt(&cmdline, "route del -net  \"%u.%u.%u.%u\" netmask ",
              ipaddr.u.addr8[0], ipaddr.u.addr8[1], ipaddr.u.addr8[2],
              ipaddr.u.addr8[3]);

    mbscatfmt(&cmdline, "%u.%u.%u.%u", netmask.u.addr8[0], netmask.u.addr8[1],
              netmask.u.addr8[2], netmask.u.addr8[3]);

    if (system(cmdline))
    {
        mbsfree(cmdline);
        return -EINTR;
    }

    mbsfree(cmdline);
    return 0;
}

uint32_t sys_clock_get(void)
{
    time_t now = time(NULL) + 1;

    return now;
}

int sys_clock_set(uint32_t clock)
{
    struct timeval tv;

    tv.tv_sec = (long)clock;
    tv.tv_usec = 0;

    if (settimeofday(&tv, NULL) < 0)
    {
        return -EINTR;
    }

    system("hwclock -w");
    return 0;
}

char* sys_datetime_get(void)
{
    time_t now = time(NULL) + 1;

    char* datetime = malloc(32);
    if (datetime == NULL)
    {
        return NULL;
    }

    strftime(datetime, 32, "%F,%T", localtime(&now));

    return datetime;
}

int sys_datetime_set(char* datetime)
{
    char* pos = NULL;

    if (datetime == NULL)
        return -EINVAL;

    pos = strchr(datetime, ',');
    if (pos == NULL)
        return -EINVAL;

    *pos = ' ';

    vasystem("date -s \"%s\"; hwclock -w", datetime);

    return 0;
}
