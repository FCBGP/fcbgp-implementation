/*
 *  获取网口信息，IP地址，MAC地址，状态，带宽等
 *
 *  日期：2020年10月16日
 *  作者：RToax
 */
#ifndef __IF_INFO_H
#define __IF_INFO_H 1


/*
 *  struct ifinfo - 网卡信息结构
 *
 *  if_idx  网口在系统中的索引，          这里需要注意的是，派生的网口 em1:1 与 em1 的索引相同
 *  if_name 网口名，例如：eth0
 *  if_flag 网口状态，参见 IFSTAT_XXX 宏定义
 *  if_ipv4 网口IP地址，例如：10.170.6.66
 *  if_eth.if_ethmac    网口MAC地址，格式：28:6E:D4:88:C7:9A
 *  if_eth.if_ethspeed  网口带宽，单位：Mbps
 */
struct ifinfo {
    unsigned int if_idx;    //接口索引号
    char if_name[32];       //接口名 如：eth0

    int if_flag;
#define IFSTAT_UP           0x0001  /* 接口状态为 up */
#define IFSTAT_BROADCAST    0x0002  /* 广播地址可用 */
#define IFSTAT_LOOPBACK     0x0004  /* 该网口是回环口 */
#define IFSTAT_POINTOPOINT  0x0010  /* 点对点连接 */
#define IFSTAT_MULTICAST    0x0020  /* 支持多播 */

    char if_ipv4[16];       //接口IPv4地址
    struct {
        char if_ethmac[64];         //MAC地址
        unsigned int if_ethspeed;   //速率 Mbps
    }if_eth;
};

/*
 *  ifinfo_display - 网口状态查询回调函数
 *
 *  info    网口信息结构指针，参见： struct ifinfo 说明
 *  arg     调用 get_ifinfo 内存地址传入的 arg 地址指针
 */
typedef void (*ifinfo_display)(const struct ifinfo *info, void *arg);


/*
 *  get_ifinfo - 获取网口信息
 *
 *    该接口可以获取网口的速率，但是，在虚拟机环境中，无法查询网口带宽
 *
 *  display_fn  查询的回调函数，参见： ifinfo_display 说明
 *  arg         回调函数被调用时的 arg 参数，该参数可以为 NULL
 *
 *  return      失败，返回 -1， 成功，返回查询的网口总数
 */
int get_ifinfo(ifinfo_display display_fn, void *arg);


#endif /*<__IF_INFO_H>*/
