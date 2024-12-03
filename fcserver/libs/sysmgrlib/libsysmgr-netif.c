#include <arpa/inet.h>
#include <errno.h>
#include <linux/sockios.h>
#include <net/if.h>
#include <net/route.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

int sys_netif_ethaddr_get(char* device, uint8_t* ethaddr)
{
    int ret;
    char buf[sizeof(struct ifreq)] = {
        0,
    };
    struct ifreq* ifr = (struct ifreq*)buf;
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0)
        return -ENOTSOCK;

    strcpy(ifr->ifr_name, device);
    ret = ioctl(sockfd, SIOCGIFHWADDR, ifr);
    close(sockfd);
    if (ret < 0)
    {
        return -ENOTTY;
    }

    memcpy(ethaddr, ifr->ifr_hwaddr.sa_data, ETH_ALEN);
    return 0;
}

int sys_netif_ethaddr_set(char* device, uint8_t* ethaddr)
{
    int ret;
    char buf[sizeof(struct ifreq)] = {
        0,
    };
    struct ifreq* ifr = (struct ifreq*)buf;
    struct sockaddr* sockaddr = (struct sockaddr*)&(ifr->ifr_hwaddr);

    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0)
        return -ENOTSOCK;

    sockaddr->sa_family = ARPHRD_ETHER;
    memcpy(sockaddr->sa_data, ethaddr, ETH_ALEN);

    strcpy(ifr->ifr_name, device);
    ret = ioctl(sockfd, SIOCSIFHWADDR, ifr);
    close(sockfd);
    if (ret < 0)
    {
        return -ENOTTY;
    }

    return 0;
}

int sys_netif_ipaddr_get(char* device, char* ipaddr)
{
    int ret;
    char buf[sizeof(struct ifreq)] = {
        0,
    };
    struct ifreq* ifr = (struct ifreq*)buf;
    struct sockaddr_in* sockaddr = (struct sockaddr_in*)&(ifr->ifr_addr);

    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0)
        return -ENOTSOCK;

    strcpy(ifr->ifr_name, device);
    ret = ioctl(sockfd, SIOCGIFADDR, ifr);
    close(sockfd);
    if (ret < 0)
    {
        return -ENOTTY;
    }

    strcpy(ipaddr, inet_ntoa(sockaddr->sin_addr));
    return 0;
}

int sys_netif_ipaddr_set(char* device, char* ipaddr)
{
    int ret;
    char buf[sizeof(struct ifreq)] = {
        0,
    };
    struct ifreq* ifr = (struct ifreq*)buf;
    struct sockaddr_in* sockaddr = (struct sockaddr_in*)&(ifr->ifr_addr);

    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0)
        return -ENOTSOCK;

    sockaddr->sin_family = AF_INET;
    sockaddr->sin_addr.s_addr = inet_addr(ipaddr);

    strcpy(ifr->ifr_name, device);
    ret = ioctl(sockfd, SIOCSIFADDR, ifr);
    close(sockfd);
    if (ret < 0)
    {
        return -ENOTTY;
    }

    return 0;
}

int sys_netif_ipmask_get(char* device, char* ipmask)
{
    int ret;
    char buf[sizeof(struct ifreq)] = {
        0,
    };
    struct ifreq* ifr = (struct ifreq*)buf;
    struct sockaddr_in* sockaddr = (struct sockaddr_in*)&(ifr->ifr_netmask);

    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0)
        return -ENOTSOCK;

    strcpy(ifr->ifr_name, device);
    ret = ioctl(sockfd, SIOCGIFNETMASK, ifr);
    close(sockfd);
    if (ret < 0)
    {
        return -ENOTTY;
    }

    strcpy(ipmask, inet_ntoa(sockaddr->sin_addr));
    return 0;
}

int sys_netif_ipmask_set(char* device, char* ipmask)
{
    int ret;
    char buf[sizeof(struct ifreq)] = {
        0,
    };
    struct ifreq* ifr = (struct ifreq*)buf;
    struct sockaddr_in* sockaddr = (struct sockaddr_in*)&(ifr->ifr_netmask);

    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0)
        return -ENOTSOCK;

    sockaddr->sin_family = AF_INET;
    sockaddr->sin_addr.s_addr = inet_addr(ipmask);

    strcpy(ifr->ifr_name, device);
    ret = ioctl(sockfd, SIOCSIFNETMASK, ifr);
    close(sockfd);
    if (ret < 0)
    {
        return -ENOTTY;
    }

    return 0;
}

int sys_netif_gateway_add(char* gateway)
{
    int ret;
    struct rtentry rt;
    struct sockaddr_in sockaddr = {.sin_family = PF_INET, .sin_port = 0};

    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0)
        return -ENOTSOCK;

    sockaddr.sin_addr.s_addr = inet_addr(gateway);

    memset(&rt, 0, sizeof(struct rtentry));

    rt.rt_flags = (RTF_UP | RTF_GATEWAY);
    rt.rt_dst.sa_family = PF_INET;
    rt.rt_genmask.sa_family = PF_INET;

    memcpy(&rt.rt_gateway, &sockaddr, sizeof(struct sockaddr));

    ret = ioctl(sockfd, SIOCADDRT, &rt);
    close(sockfd);
    if (ret < 0)
    {
        return -ENOTTY;
    }

    return 0;
}

int sys_netif_enable(char* device)
{
    int ret;
    struct ifreq ifr;
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0)
        return -ENOTSOCK;

    strcpy(ifr.ifr_name, device);
    ret = ioctl(sockfd, SIOCGIFFLAGS, &ifr);
    if (ret < 0)
    {
        close(sockfd);
        return -ENOTTY;
    }

    ifr.ifr_flags |= IFF_UP;
    ret = ioctl(sockfd, SIOCSIFFLAGS, &ifr);
    if (ret < 0)
    {
        close(sockfd);
        return -ENOTTY;
    }

    close(sockfd);
    return 0;
}

int sys_netif_disable(char* device)
{
    int ret;
    struct ifreq ifr;
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0)
        return -ENOTSOCK;

    strcpy(ifr.ifr_name, device);
    ret = ioctl(sockfd, SIOCGIFFLAGS, &ifr);
    if (ret < 0)
    {
        close(sockfd);
        return -ENOTTY;
    }

    ifr.ifr_flags &= ~IFF_UP;
    ret = ioctl(sockfd, SIOCSIFFLAGS, &ifr);
    if (ret < 0)
    {
        close(sockfd);
        return -ENOTTY;
    }

    close(sockfd);
    return 0;
}

int sys_netif_mtu_get(char* device, int* mtu)
{
    int ret;
    struct ifreq ifr;
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0)
        return -ENOTSOCK;

    strcpy(ifr.ifr_name, device);
    ret = ioctl(sockfd, SIOCGIFMTU, &ifr);
    if (ret < 0)
    {
        close(sockfd);
        return -ENOTTY;
    }

    *mtu = ifr.ifr_mtu;
    close(sockfd);
    return 0;
}

int sys_netif_mtu_set(char* device, int mtu)
{
    int ret;
    struct ifreq ifr;
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0)
        return -ENOTSOCK;

    ifr.ifr_mtu = mtu;
    strcpy(ifr.ifr_name, device);
    ret = ioctl(sockfd, SIOCSIFMTU, &ifr);
    if (ret < 0)
    {
        close(sockfd);
        return -ENOTTY;
    }

    close(sockfd);
    return 0;
}

int sys_netif_promisc_enable(char* device)
{
    int ret;
    struct ifreq ifr;
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0)
        return -ENOTSOCK;

    strcpy(ifr.ifr_name, device);
    ret = ioctl(sockfd, SIOCGIFFLAGS, &ifr);
    if (ret < 0)
    {
        close(sockfd);
        return -ENOTTY;
    }

    ifr.ifr_flags |= IFF_PROMISC;
    ret = ioctl(sockfd, SIOCSIFFLAGS, &ifr);
    if (ret < 0)
    {
        close(sockfd);
        return -ENOTTY;
    }

    close(sockfd);
    return 0;
}

int sys_netif_promisc_disable(char* device)
{
    int ret;
    struct ifreq ifr;
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0)
        return -ENOTSOCK;

    strcpy(ifr.ifr_name, device);
    ret = ioctl(sockfd, SIOCGIFFLAGS, &ifr);
    if (ret < 0)
    {
        close(sockfd);
        return -ENOTTY;
    }

    ifr.ifr_flags &= ~IFF_PROMISC;
    ret = ioctl(sockfd, SIOCSIFFLAGS, &ifr);
    if (ret < 0)
    {
        close(sockfd);
        return -ENOTTY;
    }

    close(sockfd);
    return 0;
}
