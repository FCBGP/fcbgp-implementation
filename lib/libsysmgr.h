#ifndef _LIBSYSMGR_H_
#define _LIBSYSMGR_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <ctype.h>
#include <errno.h>
#include <sched.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/vfs.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <sys/utsname.h>
#include <sys/sysinfo.h>

#include "libmbs.h"

#define SYS_PROC_PATH "/proc/"
#define SYS_ETC_PATH "/etc/"
#define FLASH_PARTITION_DATA "/dev/sda1"

static inline unsigned long parse_hex32(char *str)
{
    int a0, a1, a2, a3;

    sscanf(str, "%02x%02x%02x%02x", &a0, &a1, &a2, &a3);
    return (((a0 & 0xFF) << 24) | ((a1 & 0xFF) << 16) | ((a2 & 0xFF) << 8) | a3);
}

static inline unsigned short parse_hex16(char *str)
{
    int a0, a1;

    sscanf(str, "%02x%02x", &a0, &a1);
    return ((a0 & 0xFF) << 8) | a1;
}

typedef struct sys_netdevinfo_st {
    char name[16];
    unsigned long long rx_packets;
    unsigned long long tx_packets;
    unsigned long long rx_bytes;
    unsigned long long tx_bytes;
    unsigned long rx_errors;
    unsigned long tx_errors;
    unsigned long rx_dropped;
    unsigned long tx_dropped;
    unsigned long rx_multicast;
    unsigned long rx_compressed;
    unsigned long tx_compressed;
    unsigned long rx_frame_errors;
    unsigned long rx_fifo_errors;
    unsigned long tx_carrier_errors;
    unsigned long tx_fifo_errors;
    unsigned long collisions;

    struct sys_netdevinfo_st *prev;
    struct sys_netdevinfo_st *next;
} sys_netdevinfo_t;

typedef struct sys_pidinfo_st {
    char name[32];
    int pid;
    char state;
    long mem_rss;
    long mem_shared;
    long long time;
    long time_s;
    int pcpu;
    long priority;
    long nice;
    int sched;
    char *sched_str;

    struct sys_pidinfo_st *next;
} sys_pidinfo_t;

typedef struct sys_routeinfo_st {
    char ifname[16];
    unsigned long rt_ldest;
    unsigned long rt_lgway;
    unsigned long rt_lmask;
    int rt_flags;
    int rt_ref;
    int rt_use;
    int rt_metric;
    int rt_mtu;
    int rt_window;
    int rt_irtt;

    struct sys_routeinfo_st *next;
} sys_routeinfo_t;

typedef struct sys_tcpinfo_st {
    int slot;
    unsigned long laddr;
    unsigned long raddr;
    unsigned int rport;
    unsigned int lport;
    const char *state;

    struct sys_tcpinfo_st *next;
} sys_tcpinfo_t;

typedef sys_tcpinfo_t sys_udpinfo_t;

typedef struct sys_arpinfo_st {
    char ipaddr[20];
    char mask[8];
    char ifname[16];
    unsigned int hwtype;
    unsigned int flags;
    unsigned int hwaddr[6];

    struct sys_arpinfo_st *next;
} sys_arpinfo_t;

typedef struct sys_cpuinfo_st {
    char name[8];
    unsigned int user;
    unsigned int nice;
    unsigned int system;
    unsigned int idle;
    unsigned int iowait;
    unsigned int irq;
    unsigned int softirq;
    unsigned int total;
    int percent;

    struct sys_cpuinfo_st *next;
} sys_cpuinfo_t;

typedef struct sys_diskinfo_st {
    char filesystem[1024];
    char mounted_on[1024];
    unsigned long blocks;
    unsigned long used;
    unsigned long available;
    unsigned int usage_rate;
    struct sys_diskinfo_st *next;
} sys_diskinfo_t;

typedef struct sys_meminfo_st {
    unsigned int total;
    unsigned int used;
    unsigned available;
} sys_meminfo_t;

typedef struct sys_info_st {
    struct utsname uname;
    struct sysinfo sysinfo;

    sys_meminfo_t *meminfo;
    sys_cpuinfo_t *cpuinfo;
    sys_diskinfo_t *diskinfo;

    long time;
    int cpu_cnt;
    int disk_cnt;
    int cpu_endian;
    int cpu_width;
    int cpu_pagesize;
    int cpu_temperature;
} sys_info_t;

/* libsysmgr-arpinfo.c */
extern int sys_arpinfo_get(sys_arpinfo_t **parpinfos);
extern int sys_arpinfo_free(sys_arpinfo_t *arpinfos);
/* libsysmgr-cpuinfo.c */
extern int sys_cpuinfo_get(sys_cpuinfo_t **pcpuinfos);
extern int sys_cpuinfo_free(sys_cpuinfo_t *cpuinfos);
/* libsysmgr-diskinfo.c */
extern int sys_diskinfo_get(sys_diskinfo_t **pdiskinfos);
extern int sys_diskinfo_free(sys_diskinfo_t *diskinfos);
/* libsysmgr-meminfo.c */
extern int sys_meminfo_get(sys_meminfo_t **pmeminfo);
extern int sys_meminfo_free(sys_meminfo_t *meminfo);
/* libsysmgr-netdevinfo.c */
extern int sys_netdevinfo_get(sys_netdevinfo_t **pnetdevinfos);
extern int sys_netdevinfo_free(sys_netdevinfo_t *netdevinfos);
/* libsysmgr-netif.c */
extern int sys_netif_ethaddr_get(char *device, uint8_t *ethaddr);
extern int sys_netif_ethaddr_set(char *device, uint8_t *ethaddr);
extern int sys_netif_ipaddr_get(char *device, char *ipaddr);
extern int sys_netif_ipaddr_set(char *device, char *ipaddr);
extern int sys_netif_ipmask_get(char *device, char *ipmask);
extern int sys_netif_ipmask_set(char *device, char *ipmask);
extern int sys_netif_gateway_add(char *gateway);
extern int sys_netif_enable(char *device);
extern int sys_netif_disable(char *device);
extern int sys_netif_mtu_get(char *device, int *mtu);
extern int sys_netif_mtu_set(char *device, int mtu);
extern int sys_netif_promisc_enable(char *device);
extern int sys_netif_promisc_disable(char *device);
/* libsysmgr-pidinfo.c */
extern int sys_pidinfo_gets(sys_pidinfo_t **ppidinfos);
extern int sys_pidinfo_free(sys_pidinfo_t *pidinfos);
extern int sys_check_process(char *appname);
/* libsysmgr-routeinfo.c */
extern int sys_routeinfo_get(sys_routeinfo_t **prouteinfos, int flags);
extern int sys_routeinfo_free(sys_routeinfo_t *routeinfos);
/* libsysmgr-tcpudpinfo.c */
extern int sys_udpinfo_get(sys_udpinfo_t **pudpinfos);
extern int sys_tcpinfo_get(sys_tcpinfo_t **ptcpinfos);
extern int sys_tcpinfo_free(sys_tcpinfo_t *tcpinfos);
extern int sys_udpinfo_free(sys_udpinfo_t *udpinfos);
/* libsysmgr.c */
extern int sys_temperature_get(void);
extern mbs_t sys_bootver_get(char *filename, char *pattern);
extern mbs_t sys_linuxver_get(void);
extern mbs_t sys_rootfsver_get(void);
extern int sys_info_get(sys_info_t **psysinfo);
extern int sys_info_free(sys_info_t *sysinfo);
extern char *sys_dmesg(void);
extern char *sys_ifconfig(void);
extern int sys_reboot(void);
extern int sys_poweroff(void);
extern int sys_route_add(char *ipaddr_str, char *netmask_str, char *gwaddr_str);
extern int sys_route_del(char *ipaddr_str, char *netmask_str);
extern uint32_t sys_clock_get(void);
extern int sys_clock_set(uint32_t clock);
extern char * sys_datetime_get(void);
extern int sys_datetime_set(char *datetime);

#endif
