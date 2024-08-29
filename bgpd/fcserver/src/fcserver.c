/********************************************************************************
 * File Name:    fcserver.c
 * Author:       basilguo@163.com
 * Created Time: 2023-09-25 10:09:53
 * Description:  FC SERVER UTILS.
 *  One could receive IPv4 data with IPv6 API.
 *  and also distinguish it with getsockopt.
 ********************************************************************************/

#include <Python.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "dbutils.h"
#include "fcconfig.h"
#include "fcserver.h"
#include "hashutils.h"
#include "libdiag.h"
#include "libncs6.h"
#include "nftutils.h"
#include "pyutils.h"
#include "sigutils.h"

#define fc_error_foreach_server       \
    _(SOCK_SOCKET, "socket()")        \
    _(SOCK_OPT, "setsockopt()")       \
    _(SOCK_BIND, "bind()")            \
    _(SOCK_LISTEN, "listen()")        \
    _(SOCK_ACCEPT, "accept()")        \
    _(SOCK_CONNECT, "connect()")      \
    _(SOCK_SEND, "send()")            \
    _(SOCK_RECV, "recv()")            \
    _(EPOLL_CTL, "epoll_ctl()")       \
    _(EPOLL_CREATE, "epoll_create()") \
    _(EPOLL_WAIT, "epoll_wait()")     \
    _(GPN, "getpeername()")           \
    _(FCNTL, "fcntl()")

typedef enum
{
    FC_ERR_SERVER_NOERR,
#define _(sym, str) FC_ERR_SERVER_##sym,
    fc_error_foreach_server
#undef _
        FC_ERR_SERVER_N,
} fc_err_sock_t;

static char *fc_err_sock_strings[] = {
#define _(sym, str) str,
    fc_error_foreach_server
#undef _
};

#define fc_print_error(err_no)               \
    do                                       \
    {                                        \
        printf("[%s: %d] error: %s\n",       \
               __func__, __LINE__,           \
               fc_err_sock_strings[err_no]); \
    } while (0)

FC_server_t g_fc_server = {0};

static int
fc_sock_get_addr_from_peer_fd(int fd, struct sockaddr *sockaddr,
                              char *ipbuf, int buffsize)
{
    int ret = 0;
    socklen_t socklen = sizeof(struct sockaddr);

    ret = getpeername(fd, sockaddr, &socklen);
    if (ret != 0)
    {
        perror("getpeername()");
        return FC_ERR_SERVER_GPN;
    }

    printf("sa family: %d, AF_INET: %d, AF_INET6: %d\n",
           sockaddr->sa_family, AF_INET, AF_INET6);
    if (AF_INET6 == sockaddr->sa_family)
    {
        struct sockaddr_in6 *in = (struct sockaddr_in6 *)sockaddr;
        inet_ntop(AF_INET6, &in->sin6_addr, ipbuf, buffsize);
    }
    else if (AF_INET == sockaddr->sa_family)
    {
        struct sockaddr_in *in = (struct sockaddr_in *)sockaddr;
        inet_ntop(AF_INET, &in->sin_addr, ipbuf, buffsize);
    }

    return FC_ERR_SERVER_NOERR;
}

static int
fc_sock_set_nonblock(int fd)
{
    int flags = 0;
    flags = fcntl(fd, F_GETFL, 0);
    flags |= O_NONBLOCK;
    return fcntl(fd, F_SETFL, flags);
}

static int
fc_mlp_server_sock()
{
    int ret = FC_ERR_SERVER_NOERR;
    int yes = 1;
    socklen_t socklen = 0;
    struct sockaddr_in6 sockaddr;

    // socket
    g_fc_server.sockfd = socket(AF_INET6, SOCK_STREAM, 0);
    if (g_fc_server.sockfd < 0)
    {
        perror("socket()");
        return FC_ERR_SERVER_SOCK_SOCKET;
    }

    // set nonblock
    ret = fc_sock_set_nonblock(g_fc_server.sockfd);
    if (ret < 0)
    {
        perror("fcntl()");
        return FC_ERR_SERVER_FCNTL;
    }

    // setsockopt reuse address
    ret = setsockopt(g_fc_server.sockfd, SOL_SOCKET, SO_REUSEADDR,
                     &yes, sizeof(int));
    if (ret == -1)
    {
        perror("setsockopt()");
        return FC_ERR_SERVER_SOCK_OPT;
    }

    // bind
    socklen = sizeof(struct sockaddr_in6);
    sockaddr.sin6_family = AF_INET6;
    sockaddr.sin6_port = htons(g_fc_server.listen_port);
    inet_pton(AF_INET6, g_fc_server.prog_addr6,
              (struct sockaddr_in6 *)&sockaddr.sin6_addr);
    socklen = sizeof(struct sockaddr_in6);
    ret = bind(g_fc_server.sockfd, (struct sockaddr *)&sockaddr, socklen);
    if (ret < 0)
    {
        perror("bind()");
        return FC_ERR_SERVER_SOCK_BIND;
    }

    // listen
    ret = listen(g_fc_server.sockfd, FC_SOCK_BACKLOG);
    if (ret < 0)
    {
        perror("listen()");
        return FC_ERR_SERVER_SOCK_LISTEN;
    }

    return ret;
}

static int
fc_mlp_server_epoll_conn()
{
    int ret = 0;
    int clisockfd = 0;
    socklen_t clisocklen = 0;
    struct sockaddr_in6 clisockaddr;
    struct epoll_event event;

    while (1)
    {
        clisockfd = accept(g_fc_server.sockfd,
                           (struct sockaddr *)&clisockaddr,
                           &clisocklen);
        if (clisockfd < 0)
        {
            if ((errno == EAGAIN) || (errno == EWOULDBLOCK))
            {
                /* we have processed all incoming connections */
                break;
            }
            else
            {
                perror("accept()");
                break;
            }
        }

        fc_sock_set_nonblock(clisockfd);
        event.data.fd = clisockfd;
        event.events = EPOLLIN | EPOLLET;
        ret = epoll_ctl(g_fc_server.epollfd, EPOLL_CTL_ADD,
                        clisockfd, &event);
        if (ret < 0)
        {
            perror("epoll_ctl()");
            return FC_ERR_SERVER_EPOLL_CTL;
        }
        printf("New connection fd: %d\n", clisockfd);
    }

    return FC_ERR_SERVER_NOERR;
}

static int
fc_mlp_server_epoll_recv(int fd, char *buff,
                         int buffsize, int *recvlen, int *done)
{
    int total = 0, count = 0, flags = 0;

    while (1)
    {
        count = recv(fd, buff + total, buffsize, flags);
        if (count < 0)
        {
            /* if errno == EAGAIN, that means we have read all data.
             * so go back to the main loop. */
            if (errno != EAGAIN)
            {
                perror("read()");
                *done = 1;
            }
            break;
        }
        else if (count == 0)
        {
            /* EOF. The remote has closed the connection. */
            *done = 1;
            break;
        }

        total += count;
    }

    struct sockaddr_in6 peer_sockaddr = {0};
    char peer_ipbuf[INET6_ADDRSTRLEN] = {0};
    fc_sock_get_addr_from_peer_fd(fd, (struct sockaddr *)&peer_sockaddr,
                                  peer_ipbuf, INET6_ADDRSTRLEN);
    printf("Recv from fd: %d, remote.addr: %s, remote.port: %d\n",
           fd, peer_ipbuf, ntohs(peer_sockaddr.sin6_port));

    *recvlen = total;

    return FC_ERR_SERVER_NOERR;
}

static int
fc_mlp_server_epoll()
{
    int ret = 0, i = 0;
    int active_events_num = 0;
    int flags = 0;
    struct epoll_event event, *events;

    events = calloc(FC_EPOLL_MAX_EVENTS, sizeof(struct epoll_event));

    // create epoll
    g_fc_server.epollfd = epoll_create1(flags);
    if (g_fc_server.epollfd < 0)
    {
        perror("epoll_create()");
        return FC_ERR_SERVER_EPOLL_CREATE;
    }

    // add server socket to epoll events
    event.data.fd = g_fc_server.sockfd;
    event.events = EPOLLIN | EPOLLET;
    ret = epoll_ctl(g_fc_server.epollfd, EPOLL_CTL_ADD,
                    g_fc_server.sockfd, &event);
    if (ret < 0)
    {
        perror("epoll_ctl()");
        return FC_ERR_SERVER_EPOLL_CTL;
    }

    // epoll event loop
    while (1)
    {
        active_events_num = epoll_wait(g_fc_server.epollfd, events,
                                       FC_EPOLL_MAX_EVENTS, -1);
        for (i = 0; i < active_events_num; ++i)
        {
            if ((events[i].events & EPOLLERR) || (events[i].events & EPOLLHUP) || (!events[i].events & EPOLLIN))
            {
                /* an error has occured on this fd,
                 * or the socket is not ready for reading */
                fprintf(stderr, "epoll error\n");
                /* closing the descriptor will make epoll remove it
                 * from the set of fds which are monitored. */
                close(events[i].data.fd);
                continue;
            }
            else if (g_fc_server.sockfd == events[i].data.fd)
            {
                /* we have a notification on the listening socket,
                 * which means one or more incoming connections. */
                ret = fc_mlp_server_epoll_conn();
                if (ret != FC_ERR_SERVER_NOERR)
                {
                    return ret;
                }
            }
            else
            {
                /* we have data on the fd waiting to be read.
                 * read and display it.
                 * we must read whatever data is available completely,
                 * as we are running in edge-triggered mode
                 * and won't get a notification again for the same data */
                char buff[FC_BUFF_SIZE] = {0};
                int recvlen = 0, done = 0;
                ret = fc_mlp_server_epoll_recv(events[i].data.fd, buff,
                                               FC_BUFF_SIZE, &recvlen, &done);
                if (ret != FC_ERR_SERVER_NOERR)
                {
                    return ret;
                }

                // process the data
                printf("fd: %d, recvlen: %d\n",
                       events[i].data.fd, recvlen);
                fc_server_handler(events[i].data.fd, buff, FC_BUFF_SIZE, recvlen);

                if (done)
                {
                    printf("Closed connection on fd: %d\n",
                           events[i].data.fd);
                    /* closing the descriptor will make epoll remove it
                     * from the set of fds which are monitored. */
                    close(events[i].data.fd);
                    printf("#################################################\n\n\n");
                }
            }
        }
    }

    free(events);

    return ret;
}

static int
fc_multi_long_pull_server(void)
{
    int ret = 0;

    /* socket */
    ret = fc_mlp_server_sock();
    if (ret < 0)
    {
        fc_print_error(ret);
        goto atexit;
    }

    printf("FCServer in AS %d is ready!!!\n", g_fc_server.local_asn);

    /* epoll */
    ret = fc_mlp_server_epoll();
    if (ret < 0)
    {
        fc_print_error(ret);
        goto atexit;
    }

    return 0;

atexit:
    close(g_fc_server.sockfd);
    close(g_fc_server.epollfd);

    return -1;
}

static int fc_server_handler_ncs(ncs6_ctx_t *ctx)
{
    (void)ctx;
    return 0;
}

static void
fc_ncs_server()
{
    if ((g_fc_server.fc_bgpd_ctx6 = ncs6_create(g_fc_server.prog_name, TCP_PROTO)) == NULL)
    {
        DIAG_ERROR("Create bgpd ncs failed\n");
        fprintf(stderr, "Create bgpd ncs failed\n");
        exit(-ENOMEM);
    }

    ncs6_setup(g_fc_server.fc_bgpd_ctx6,
               g_fc_server.prog_addr6, g_fc_server.listen_port, NULL, 0);
    ncs6_timeout(g_fc_server.fc_bgpd_ctx6, 10, -1);
    // ncs6_setkeepalive(g_fc_server.fc_bgpd_ctx6, 10);
    ncs6_server_enable(g_fc_server.fc_bgpd_ctx6);
    ncs6_server_register(g_fc_server.fc_bgpd_ctx6, fc_server_handler_ncs);
    ncs6_manager_start(g_fc_server.fc_bgpd_ctx6);
    printf("fc_server : AS %d is ready!!!\n", g_fc_server.local_asn);

    while (1)
    {
        sleep(1);
    }
}

int fc_server_create(void)
{
    FC_node_as_t meta = {0};
    FC_ht_node_as_t *node = NULL;
    FC_router_info_t *router = NULL;

    fc_db_init(&g_fc_server.db);

    meta.asn = g_fc_server.local_asn;
    node = htbl_meta_find(&g_fc_server.ht_as, &meta);
    if (!node)
    {
        DIAG_ERROR("Cannot find AS %d!!!!!!!!\n", g_fc_server.local_asn);
        fprintf(stderr, "Cannot find AS %d!!!\n", g_fc_server.local_asn);
        return -1;
    }

    switch (g_fc_server.use_data_plane)
    {
    case FC_DP_MODE_H3C:
        // py ncclient establishes sessions
        router = g_fc_server.routers;
        while (router)
        {
            py_setup(&router->py_config, "script",
                     router->host, router->username,
                     router->password, router->port);
            router = router->next;
        }
        break;
    }
    fc_multi_long_pull_server();

    return 0;
}

static int
fc_bm_sent_to_peer(const char *addr, const FC_msg_bm_t *bm,
                   char *buffer, int bufferlen)
{
    int ret = 0;
    int sockfd = 0;
    int len = 0;
    struct sockaddr_in sockaddr;

    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        perror("socket()");
        return -1;
    }
    sockaddr.sin_family = AF_INET;
    sockaddr.sin_port = htons(g_fc_server.listen_port);
    inet_pton(AF_INET, addr, &sockaddr.sin_addr);
    if ((ret = connect(sockfd, (struct sockaddr *)&sockaddr,
                       sizeof(sockaddr))) < 0)
    {
        perror("connect()");
        return -1;
    }

    while (len != bufferlen)
    {
        len = len + send(sockfd, buffer + len, bufferlen - len, 0);
        printf("len = %d, bufferlen = %d\n", len, bufferlen);
    }

    close(sockfd);

    return 0;
}

static inline bool
fc_asn_is_offpath(u32 asn, const FC_msg_bm_t *bm)
{
    int i = 0;

    for (i = 0; i < bm->fc_num; ++i)
    {
        if (asn == bm->fclist[i].previous_asn ||
            asn == bm->fclist[i].current_asn ||
            asn == bm->fclist[i].nexthop_asn)
        {
            return false;
        }
    }

    return true;
}

static int
fc_bm_find_server(uint32_t asn, char *ifaddr, char *ifname)
{
    FC_node_as_t meta;
    FC_ht_node_as_t *node;

    meta.asn = asn;
    node = htbl_meta_find(&g_fc_server.ht_as, &meta);

    if (node)
    {
        memcpy(ifaddr, node->acs.ipv4[0].ifaddr,
               strlen(node->acs.ipv4[0].ifaddr));
        if (ifname)
        {
            memcpy(ifname, node->acs.ipv4[0].ifname,
                   strlen(node->acs.ipv4[0].ifname));
        }
        return 0;
    }

    return -1;
}

static int
fc_bm_broadcast_to_peer(int clisockfd, const FC_msg_bm_t *bm,
                        char *buffer, int bufferlen)
{
    printf("broadcast to peers start\n");
    int i = 0, ret = 0;
    u32 asn = 0;

    for (i = 0; i < g_fc_server.asns_num; ++i)
    {
        FC_node_as_t meta = {0};
        char ifaddr[INET6_ADDRSTRLEN] = {0};

        asn = g_fc_server.asns[i];
        if (g_fc_server.local_asn == asn)
        {
            continue;
        }

        meta.asn = asn;
        FC_ht_node_as_t *node = htbl_meta_find(&g_fc_server.ht_as, &meta);

        if (node)
        {
            // offpath
            if (fc_asn_is_offpath(asn, bm))
            {
                printf("sent to offpath node: %d\n", node->asn);
                ret = fc_bm_find_server(asn, ifaddr, NULL);
                if (ret == 0)
                {
                    printf("remote-acs addr: %s\n", ifaddr);
                    fc_bm_sent_to_peer(ifaddr, bm, buffer, bufferlen);
                }
                else
                {
                    printf("Error: cannot find acs\n");
                }
            }
            // onpath
            else
            {
                printf("sent to onpath node: %d\n", node->asn);
                ret = fc_bm_find_server(asn, ifaddr, NULL);
                if (ret == 0)
                {
                    printf("remote-acs addr: %s\n", ifaddr);
                    fc_bm_sent_to_peer(ifaddr, bm, buffer, bufferlen);
                }
                else
                {
                    printf("Error: cannot find acs\n");
                }
            }
        }
    }

#if 0
    for (i=0; i<bm->fc_num; ++i)
    {
        // TODO wether asn is in aspath
        meta.asn = bm->fclist[i].current_asn;
        FC_ht_node_as_t *node = htbl_meta_find(&g_fc_server.ht_as,
                &meta);
        if (node)
        {
            if (g_fc_server.local_asn != node->asn)
            {
                printf("sent to %d\n", node->asn);
                fc_bm_sent_to_peer(node->acs.ipv4,
                        bm, buffer, bufferlen);
            }
        }
    }
#endif

    printf("broadcast to peers done\n");
    return 0;
}

int fc_server_pubkey_handler(int clisockfd, const char *buff, int len)
{
    printf("TODO pubkey\n");
    return 0;
}

static int
fc_server_topo_find_iface(FC_router_link_info_t *link_info,
                          u32 iface_index,
                          FC_router_iface_info_t **iface_info,
                          FC_router_iface_info_t **prev_iface_info)
{
    *iface_info = *prev_iface_info = link_info->iface_list;
    while (*iface_info)
    {
        if ((*iface_info)->iface_index == iface_index)
        {
            break;
        }
        *prev_iface_info = *iface_info;
        *iface_info = (*iface_info)->next;
    }

    return 0;
}

static int
fc_server_topo_find_router(FC_router_info_t *target_router,
                           u32 neighbor_asn,
                           FC_router_link_info_t **link_info,
                           FC_router_link_info_t **prev_link_info)
{
    *prev_link_info = *link_info = target_router->links;
    while (*link_info)
    {
        if ((*link_info)->neighbor_asn == neighbor_asn)
        {
            break;
        }
        *prev_link_info = *link_info;
        *link_info = (*link_info)->next;
    }

    return 0;
}

static int
fc_server_topo_del_one_link(FC_router_link_info_t *link_info,
                            u32 iface_index)
{
    FC_router_iface_info_t *prev_iface_info = NULL, *iface_info = NULL;

    fc_server_topo_find_iface(link_info,
                              iface_index, &iface_info, &prev_iface_info);

    if (iface_info)
    {
        if (prev_iface_info != iface_info)
        {
            prev_iface_info->next = iface_info->next;
        }
        else
        {
            link_info->iface_list = iface_info->next;
        }
        free(iface_info);
    }

    return 0;
}

static int
fc_server_topo_del_one_neighbor(FC_router_link_info_t *link_info)
{
    FC_router_iface_info_t *iface_info = NULL, *next_iface_info = NULL;

    iface_info = link_info->iface_list;
    while (iface_info)
    {
        next_iface_info = iface_info->next;
        free(iface_info);
        iface_info = next_iface_info;
    }
    free(link_info);

    return 0;
}

static int
fc_server_topo_del_all_neighbors(FC_router_info_t *target_router)
{
    FC_router_link_info_t *link_info = NULL, *next_link_info = NULL;

    link_info = target_router->links;
    while (link_info)
    {
        next_link_info = link_info->next;
        fc_server_topo_del_one_neighbor(link_info);
        link_info = next_link_info;
    }
    target_router->links = NULL;

    return 0;
}

/* used when destroying the fcs. */
static int
fc_server_topo_del_all_routers()
{
    FC_router_info_t *router_info = NULL, *next_router_info = NULL;

    router_info = g_fc_server.routers;
    while (router_info)
    {
        next_router_info = router_info->next;
        fc_server_topo_del_all_neighbors(router_info);
        close(router_info->fd);
        free(router_info);
        router_info = next_router_info;
    }
    g_fc_server.routers = NULL;

    return 0;
}

static int
fc_server_topo_del(FC_router_info_t *target_router,
                   u32 neighbor_num, const char *buff, int currlen)
{
    int i = 0, k = 0;
    u32 neighbor_asn = 0, il_num = 0, iface_index = 0;
    u32 *iface_list = NULL;
    FC_router_link_info_t *link_info = NULL, *prev_link_info = NULL;

    // delete all neighbors of this bgp router
    if (neighbor_num == 0xFFFFFFFF)
    {
        fc_server_topo_del_all_neighbors(target_router);
        return currlen;
    }

    iface_list = (u32 *)malloc(sizeof(u32) * il_num);
    FC_ASSERT_RETP(iface_list);

    // delete part neighbors of this bgp router
    for (i = 0; i < neighbor_num; ++i)
    {
        // neighbor-asn
        memcpy(&neighbor_asn, buff + currlen, sizeof(u32));
        neighbor_asn = ntohl(neighbor_asn);
        currlen += sizeof(u32);
        // il-num
        memcpy(&il_num, buff + currlen, sizeof(u32));
        il_num = ntohl(il_num);
        currlen += sizeof(u32);
        // iface-list
        if (il_num != 0xFFFFFFFF)
        {
            memcpy(iface_list, buff + currlen, sizeof(u32) * il_num);
            currlen += sizeof(u32) * il_num;
        }

        // find the neighbor
        prev_link_info = link_info = target_router->links;
        fc_server_topo_find_router(target_router,
                                   neighbor_asn, &link_info, &prev_link_info);
        if (link_info == NULL)
        {
            // no such neighbor
            continue;
        }

        if (il_num == 0xFFFFFFFF)
        {
            if (prev_link_info)
            {
                prev_link_info->next = link_info->next;
            }
            else
            {
                target_router->links = link_info->next;
            }
            fc_server_topo_del_one_neighbor(link_info);
        }
        else
        {
            for (k = 0; k < il_num; ++k)
            {
                // iface
                iface_index = ntohl(iface_list[k]);
                fc_server_topo_del_one_link(link_info, iface_index);
            }
        }
    }

    free(iface_list);

    return 0;
}

static int
fc_server_topo_add(FC_router_info_t *target_router,
                   u32 neighbor_num, const char *buff, int currlen)
{
    int j = 0, k = 0, ret = 0;
    u32 neighbor_asn = 0, il_num = 0, iface_index = 0;
    u32 *iface_list = NULL;
    FC_router_link_info_t *link_info = NULL, *prev_link_info = NULL;
    FC_router_iface_info_t *iface_info = NULL, *prev_iface_info = NULL;

    for (j = 0; j < neighbor_num; ++j)
    {
        // neighbor-asn
        memcpy(&neighbor_asn, buff + currlen, sizeof(u32));
        neighbor_asn = ntohl(neighbor_asn);
        currlen += sizeof(u32);
        // il-num
        memcpy(&il_num, buff + currlen, sizeof(u32));
        il_num = ntohl(il_num);
        currlen += sizeof(u32);

        // find the neighbor
        prev_link_info = link_info = target_router->links;
        fc_server_topo_find_router(target_router,
                                   neighbor_asn, &link_info, &prev_link_info);
        if (link_info == NULL)
        {
            // no such neighbor
            link_info = calloc(1, sizeof(FC_router_link_info_t));
            FC_ASSERT_RETP(link_info);
            if (prev_link_info)
            {
                prev_link_info->next = link_info;
            }
            else
            {
                target_router->links = link_info;
            }
        }
        link_info->neighbor_asn = neighbor_asn;

        // iface-list
        for (k = 0; k < il_num; ++k)
        {
            memcpy(&iface_index, buff + currlen, sizeof(u32));
            iface_index = ntohl(iface_index);
            currlen += sizeof(u32);
            fc_server_topo_find_iface(link_info,
                                      iface_index, &iface_info, &prev_iface_info);
            if (iface_info == NULL)
            {
                // no such iface
                iface_info = (FC_router_iface_info_t *)
                    calloc(1, sizeof(FC_router_iface_info_t));
                FC_ASSERT_RETP(iface_info);
                if (prev_iface_info)
                {
                    prev_iface_info->next = iface_info;
                }
                else
                {
                    link_info->iface_list = iface_info;
                }
            }
            iface_info->iface_index = iface_index;
            // insert into ht
            ret = ht_aclinfo_insert(g_fc_server.ht_aclinfo, iface_index);
            FC_ASSERT_RET(ret);
        }
    }

    return currlen;
}

int fc_server_topo_handler(int clisockfd, const char *buff, int len)
{
    printf("topo link information start\n");

    int i = 0, currlen = 0, ret = 0;
    u8 action = 0, reserved = 0;
    u32 bgpid = 0, local_asn = 0, neighbor_num = 0;
    FC_router_info_t *target_router = NULL;
    FC_router_link_info_t *link_info = NULL;

    currlen = FC_HDR_GENERAL_LENGTH;

    // action
    memcpy(&action, buff + currlen, sizeof(u8));
    currlen += sizeof(u8);
    // reserved
    for (i = 0; i < 3; ++i)
    {
        memcpy(&reserved, buff + currlen, sizeof(u8));
        currlen += sizeof(u8);
    }
    // bgpid
    memcpy(&bgpid, buff + currlen, sizeof(u32));
    bgpid = ntohl(bgpid);
    currlen += sizeof(u32);
    // local-asn
    memcpy(&local_asn, buff + currlen, sizeof(u32));
    local_asn = ntohl(local_asn);
    currlen += sizeof(u32);
    // neighbor-num
    memcpy(&neighbor_num, buff + currlen, sizeof(u32));
    neighbor_num = ntohl(neighbor_num);
    currlen += sizeof(u32);

    if (local_asn != g_fc_server.local_asn)
    {
        printf("ERROR: msg type=4, not local asn\n");
        return -1;
    }
    // g_fc_server.routers should be prepared in reading config
    for (target_router = g_fc_server.routers;
         target_router != NULL;
         target_router = target_router->next)
    {
        if (target_router->bgpid == bgpid)
        {
            break;
        }
    }

    if (target_router == NULL)
    {
        printf("ERROR: Cannot find the bgp router, bgpid: %08X\n", bgpid);
        fc_server_destroy(SIGUSR1);
    }

    // fd
    if (target_router->fd != 0 && target_router->fd != clisockfd)
    {
        // TODO del all neighbors
        // TODO close the target-link fd
    }
    target_router->fd = clisockfd;

    switch (action)
    {
    case FC_ACT_ADD:
        currlen = fc_server_topo_add(target_router,
                                     neighbor_num, buff, currlen);
        break;
    case FC_ACT_DEL:
        // TODO
        ret = fc_server_topo_del(target_router,
                                 neighbor_num, buff, currlen);
        break;
    default:
        printf("ERROR: Unkown action: %d for neighbor links\n", action);
        break;
    }

    printf("topo link information end\n");

    return 0;
}

static int
fc_bm_verify_fc(FC_msg_bm_t *bm)
{
    u8 msg[FC_BUFF_SIZE];
    int ret = 0;
    int msglen = 0;
    int i = 0, j = 0;
    u32 previous_asn = 0, current_asn = 0, nexthop_asn = 0;

    for (i = 0; i < bm->fc_num; ++i)
    {
        memset(msg, 0, FC_BUFF_SIZE);
        msglen = 0;
        // hash(prev_asn, curr_asn, next_asn, dst_ip, prefixlen)
        // asn
        previous_asn = htonl(bm->fclist[i].previous_asn);
        current_asn = htonl(bm->fclist[i].current_asn);
        nexthop_asn = htonl(bm->fclist[i].nexthop_asn);
        memcpy(msg + msglen, &previous_asn, sizeof(u32));
        msglen += sizeof(u32);
        memcpy(msg + msglen, &current_asn, sizeof(u32));
        msglen += sizeof(u32);
        memcpy(msg + msglen, &nexthop_asn, sizeof(u32));
        msglen += sizeof(u32);
        // dst_ip
        for (j = 0; j < bm->dst_ip_num; ++j)
        {
            if (bm->ipversion == IPV4)
            {
                u32 ip4 = ((struct sockaddr_in *)&(bm->dst_ip[j].ip))->sin_addr.s_addr;
                memcpy(msg + msglen, &ip4, IP4_LENGTH);
                msglen += IP4_LENGTH;
            }
            else
            {
                struct sockaddr_in6 *ip6;
                ip6 = (struct sockaddr_in6 *)&(bm->dst_ip[j].ip);
                memcpy(msg + msglen, &(ip6->sin6_addr), IP6_LENGTH);
                msglen += IP6_LENGTH;
            }
            memcpy(msg + msglen, &bm->dst_ip[j].prefix_length, 1);
            msglen += 1;
        }

        printf("raw msg for verify fc: ");
        for (int k = 0; k < msglen; ++k)
        {
            printf("%02X", msg[k]);
        }
        printf("\n");

        FC_ht_node_as_t *node;
        FC_node_as_t meta = {0};
        meta.asn = bm->fclist[i].current_asn;
        node = htbl_meta_find(&g_fc_server.ht_as, &meta);

        printf("g_fc_server.local_asn: %u, bm.local_asn: %u, node.asn: %u\n",
               g_fc_server.local_asn, bm->local_asn, node->asn);
        printf("g_fc_server.ski: ");
        for (int k = 0; k < FC_SKI_LENGTH; ++k)
        {
            printf("%02X", g_fc_server.ski[k]);
        }
        printf("\n");
        printf("bm.ski: ");
        for (int k = 0; k < FC_SKI_LENGTH; ++k)
        {
            printf("%02X", bm->ski[k]);
        }
        printf("\n");
        printf("node.ski: ");
        for (int k = 0; k < FC_SKI_LENGTH; ++k)
        {
            printf("%02X", node->ski[k]);
        }
        printf("\n");

        ret = fc_ecdsa_verify(node->pubkey, msg, msglen,
                              bm->fclist[i].sig, bm->fclist[i].siglen);
        switch (ret)
        {
        case 1:
            printf("verify fc %d ok\n", i);
            break;
        case 0:
            printf("verify fc %d failed\n", i);
            break;
        default:
            printf("verify fc %d error\n", i);
            break;
        }
    }
    return 0;
}

static int
fc_gen_acl_linux(int clisockfd, const FC_msg_bm_t *bm)
{
    int i = 0, j = 0, ret = 0;
    bool flag_offpath = false;
    char ifaddr[INET6_ADDRSTRLEN] = {0}, ifname[FC_MAX_SIZE] = {0};
    char saddr[INET6_ADDRSTRLEN] = {0};
    char daddr[INET6_ADDRSTRLEN] = {0};
    u32 asn = 0;

    asn = bm->fclist[0].current_asn;
    char ipbuf[INET6_ADDRSTRLEN] = {0};
    struct sockaddr_in6 sockaddr;

    fc_sock_get_addr_from_peer_fd(clisockfd, (struct sockaddr *)&sockaddr,
                                  ipbuf, INET6_ADDRSTRLEN);
    if (strcmp("127.0.0.1", ipbuf) != 0)
    {
        asn = bm->fclist[0].nexthop_asn;
    }

    ret = fc_bm_find_server(asn, ifaddr, ifname);
    if (ret < 0)
    {
        printf("ERROR: there is no such asn: %u\n", asn);
    }
    printf("-=+=-# ifaddr %s, ifname %s #-=+=-\n", ifaddr, ifname);
    flag_offpath = fc_asn_is_offpath(g_fc_server.local_asn, bm);

    inet_ntop(AF_INET, &(((struct sockaddr_in *)&(bm->dst_ip[0].ip))->sin_addr),
              daddr, (socklen_t)sizeof(daddr));

    for (i = 0; i < bm->src_ip_num; ++i)
    {
        // TODO ipv6
        inet_ntop(AF_INET, &(((struct sockaddr_in *)&(bm->src_ip[i].ip))->sin_addr),
                  saddr, (socklen_t)sizeof(saddr));
        char cmd[1000] = {0};
        if (flag_offpath) // filter: s->d
        {
            for (j = FC_NFT_FILTER_CHAIN_START; j < FC_NFT_FILTER_CHAIN_END; ++j)
            {
                sprintf(cmd, "nft add rule inet filter %s "
                             "ip saddr %s/%d ip daddr %s/%d drop",
                        g_fc_nft_chains[j],
                        saddr, bm->src_ip[0].prefix_length,
                        daddr, bm->dst_ip[0].prefix_length);
                ret = system(cmd);
                // printf("ret = %d, cmd: %s\n", ret, cmd);
            }
        }
        else // filter: !a->d
        {
            for (j = 0; j < g_fc_server.nics_num; ++j)
            {
                if (strcmp(g_fc_server.nics[j], ifname))
                {
                    /*
                     * sudo nft add rule inet filter output oif ens36 \
                     *      ip saddr 192.168.88.131 ip daddr 192.168.88.132 drop
                     * */
                    if (bm->fclist[0].nexthop_asn == g_fc_server.local_asn)
                    {
                        sprintf(cmd, "nft add rule inet filter %s "
                                     "oifname %s ip saddr %s/%d ip daddr %s/%d drop",
                                g_fc_nft_chains[FC_NFT_FILTER_CHAIN_OUTPUT],
                                g_fc_server.nics[j],
                                saddr, bm->src_ip[0].prefix_length,
                                daddr, bm->dst_ip[0].prefix_length);
                    }
                    else
                    {
                        sprintf(cmd, "nft add rule inet filter %s "
                                     "iifname %s ip saddr %s/%d ip daddr %s/%d drop",
                                bm->fc_num > 1 ? g_fc_nft_chains[FC_NFT_FILTER_CHAIN_FORWARD]
                                               : g_fc_nft_chains[FC_NFT_FILTER_CHAIN_INPUT],
                                g_fc_server.nics[j],
                                saddr, bm->src_ip[0].prefix_length,
                                daddr, bm->dst_ip[0].prefix_length);
                    }
                    ret = system(cmd);
                    // printf("ret = %d, cmd: %s\n", ret, cmd);
                }
            }
        }
    }

    return 0;
}

static int
fc_gen_acl_h3c(int clisockfd, const FC_msg_bm_t *bm)
{
    int i = 0, j = 0, ret = 0, iface_index = 0, fc_index = 0;
    u32 asn = 0;
    bool flag_offpath = 0;
    FC_router_info_t *router_info = NULL;
    FC_router_link_info_t *link_info = NULL;
    FC_router_iface_info_t *iface_info = NULL;
    char ifaddr[INET6_ADDRSTRLEN] = {0};
    char ifname[FC_MAX_SIZE] = {0};
    char saddr[INET6_ADDRSTRLEN] = {0};
    char daddr[INET6_ADDRSTRLEN] = {0};
    int sprefixlen = 0, dprefixlen = 0;
    char ipbuf[INET6_ADDRSTRLEN] = {0};
    struct sockaddr_in6 sockaddr;
    int direction = 0; // 1 for in, 2 for out, 3 for both

    fc_sock_get_addr_from_peer_fd(clisockfd, (struct sockaddr *)&sockaddr,
                                  ipbuf, INET6_ADDRSTRLEN);

    for (fc_index = 0; fc_index < bm->fc_num; ++fc_index)
    {
        if (bm->fclist[fc_index].current_asn == g_fc_server.local_asn)
        {
            flag_offpath = false;
            break;
        }
    }

    // maybe can be removed as dst_ip_num is always 1
    for (i = 0; i < bm->dst_ip_num; ++i)
    {
        if (bm->ipversion == 4)
        {
            inet_ntop(AF_INET,
                      &(((struct sockaddr_in *)&(bm->dst_ip[i].ip))->sin_addr),
                      daddr, (socklen_t)sizeof(daddr));
        }
        else if (bm->ipversion == 6)
        {
            inet_ntop(AF_INET6,
                      &(((struct sockaddr_in6 *)&(bm->dst_ip[i].ip))->sin6_addr),
                      daddr, (socklen_t)sizeof(daddr));
        }
        dprefixlen = bm->dst_ip[i].prefix_length;
        for (j = 0; j < bm->src_ip_num; ++j)
        {
            if (bm->ipversion == IPV4)
            {
                inet_ntop(AF_INET,
                          &(((struct sockaddr_in *)&(bm->src_ip[j].ip))->sin_addr),
                          saddr, (socklen_t)sizeof(saddr));
            }
            else if (bm->ipversion == IPV6)
            {
                inet_ntop(AF_INET6,
                          &(((struct sockaddr_in6 *)&(bm->src_ip[j].ip))->sin6_addr),
                          saddr, (socklen_t)sizeof(saddr));
            }
            sprefixlen = bm->src_ip[j].prefix_length;
            router_info = g_fc_server.routers;
            // actually, there may be no so many devices
            while (router_info)
            {
                link_info = router_info->links;
                while (link_info)
                {
                    iface_info = link_info->iface_list;
                    while (iface_info)
                    {
                        ht_aclinfo_t *item = NULL;
                        item = mln_hash_search(g_fc_server.ht_aclinfo,
                                               &iface_info->iface_index);
                        FC_ASSERT_RETP(item);
                        if (flag_offpath)
                        {
                            // offpath
                            printf("srcip: %s/%d, dstip: %s/%d, iface_index: %d,"
                                   " direction: %s\n",
                                   saddr, sprefixlen, daddr, dprefixlen,
                                   iface_info->iface_index, "both");
                            // h3c device has only dir=1: in, dir=2: out
                            py_apply_acl(&router_info->py_config,
                                         item->acl_in_index, bm->ipversion,
                                         saddr, sprefixlen, daddr, dprefixlen,
                                         iface_info->iface_index, 1);
                            py_apply_acl(&router_info->py_config,
                                         item->acl_out_index, bm->ipversion,
                                         saddr, sprefixlen, daddr, dprefixlen,
                                         iface_info->iface_index, 2);
                        }
                        else
                        {
                            if (link_info->neighbor_asn == bm->fclist[fc_index].nexthop_asn)
                            {
                                direction = 1; // in
                            }
                            else if (link_info->neighbor_asn == bm->fclist[fc_index].previous_asn)
                            {
                                direction = 2;
                            }
                            else
                            {
                                direction = 3;
                            }

                            // onpath
                            printf("srcip: %s/%d, dstip: %s/%d, "
                                   "iface_index: %d, direction: %s\n",
                                   saddr, sprefixlen, daddr, dprefixlen,
                                   iface_info->iface_index,
                                   direction == 3 ? "both" : (direction == 1 ? "in" : "out"));
                            // h3c device has only dir=1: in, dir=2: out
                            if (direction & 0x1)
                            {
                                py_apply_acl(&router_info->py_config,
                                             item->acl_in_index, bm->ipversion,
                                             saddr, sprefixlen, daddr, dprefixlen,
                                             iface_info->iface_index, 1);
                            }
                            if (direction & 0x2)
                            {
                                py_apply_acl(&router_info->py_config,
                                             item->acl_out_index, bm->ipversion,
                                             saddr, sprefixlen, daddr, dprefixlen,
                                             iface_info->iface_index, 2);
                            }
                        }
                        iface_info = iface_info->next;
                    }
                    link_info = link_info->next;
                }
                router_info = router_info->next;
            }
        }
    }

    return 0;
}

static int
fc_gen_acl(int clisockfd, const FC_msg_bm_t *bm)
{

    switch (g_fc_server.use_data_plane)
    {
    case FC_DP_MODE_LINUX:
        fc_gen_acl_linux(clisockfd, bm);
        break;
    case FC_DP_MODE_H3C:
        fc_gen_acl_h3c(clisockfd, bm);
        break;
    case FC_DP_MODE_NONE:
        break;
    default:
        printf("NOT SUPPORTED DP MODE: %d\n",
               g_fc_server.use_data_plane);
        break;
    }

    return 0;
}

static void fc_bm_print(const FC_msg_bm_t *bm)
{
    int i = 0, j = 0;
    struct sockaddr_in *in4 = NULL;
    struct sockaddr_in6 *in6 = NULL;
    char ipstr[INET6_ADDRSTRLEN];
    printf("bm version: %d\n", bm->bmversion);
    printf("ip version: %d\n", bm->ipversion);
    printf("flags: %02X\n", bm->flags);
    printf("algoid: %d\n", bm->algoid);
    printf("src ip prefix num: %d\n", bm->src_ip_num);
    printf("dst ip prefix num: %d\n", bm->dst_ip_num);
    printf("fc num: %d\n", bm->fc_num);
    printf("siglen: %d\n", bm->siglen);
    printf("local_asn: %08X\n", bm->local_asn);
    printf("version: %08X\n", bm->version);
    printf("subversion: %08X\n", bm->subversion);

    printf("src ip prefix:\n");
    for (i = 0; i < bm->src_ip_num; ++i)
    {
        memset(ipstr, 0, INET6_ADDRSTRLEN);
        printf("  idx: %d, ", i);
        switch (bm->ipversion)
        {
        case IPV4:
            inet_ntop(AF_INET,
                      &((struct sockaddr_in *)&bm->src_ip[i].ip)->sin_addr,
                      ipstr, sizeof(struct sockaddr_in));
            printf("%s/%d\n", ipstr, bm->src_ip[i].prefix_length);
            break;
        case IPV6:
            inet_ntop(AF_INET6,
                      &((struct sockaddr_in6 *)&bm->src_ip[i].ip)->sin6_addr,
                      ipstr, sizeof(struct sockaddr_in6));
            printf("%s/%d\n", ipstr, bm->src_ip[i].prefix_length);
            break;
        }
    }
    printf("dst ip prefix:\n");
    for (i = 0; i < bm->dst_ip_num; ++i)
    {
        memset(ipstr, 0, INET6_ADDRSTRLEN);
        printf("  idx: %d, ", i);
        switch (bm->ipversion)
        {
        case IPV4:
            inet_ntop(AF_INET,
                      &((struct sockaddr_in *)&bm->dst_ip[i].ip)->sin_addr,
                      ipstr, sizeof(struct sockaddr_in));
            printf("%s/%d\n", ipstr, bm->dst_ip[i].prefix_length);
            break;
        case IPV6:
            inet_ntop(AF_INET6,
                      &((struct sockaddr_in6 *)&bm->dst_ip[i].ip)->sin6_addr,
                      ipstr, sizeof(struct sockaddr_in6));
            printf("%s/%d\n", ipstr, bm->dst_ip[i].prefix_length);
            break;
        }
    }
    printf("fc list:\n");
    for (i = 0; i < bm->fc_num; ++i)
    {
        printf("  idx: %d, 3 asn: %d, %d, %d, algo-id: %d, flags: %d, siglen: %d sig: ",
               i,
               bm->fclist[i].previous_asn,
               bm->fclist[i].current_asn,
               bm->fclist[i].nexthop_asn,
               bm->fclist[i].algo_id,
               bm->fclist[i].flags,
               bm->fclist[i].siglen);

        for (int k = 0; k < bm->fclist[i].siglen; ++k)
        {
            printf("%02X", bm->fclist[i].sig[k]);
        }
        printf("\n");
    }
    printf("ski: ");
    for (i = 0; i < FC_SKI_LENGTH; ++i)
    {
        printf("%02X", bm->ski[i]);
    }
    printf("\n");
}

// buff is starting from bm's ipversion
// msg_type: is broadcast msg
int fc_server_bm_handler(int clisockfd, char *buffer,
                         int bufferlen, int msg_type)
{
    char buff_new_msg[FC_BUFF_SIZE] = {0};
    memcpy(buff_new_msg, buffer, bufferlen);
    char *buff = buff_new_msg + FC_HDR_GENERAL_LENGTH;

    int i = 0;
    FC_msg_bm_t bm = {0};
    int cur = 0;
    int ret = 0;
    int ip_len = 0;
    char msg[FC_BUFF_SIZE] = {0};
    unsigned char *sigbuff = NULL;
    unsigned int sigbufflen = 0;

    // bmversion
    switch (buff[0])
    {
    case FC_BM_VERSION: // current bm version
        break;
    default:
        fprintf(stderr, "BM version %d is not supported\n", buff[0]);
        return -1;
    }

    // ipversion
    switch (buff[1])
    {
    case IPV4: // ipv4
        ip_len = IP4_LENGTH;
        break;
    case IPV6: // ipv6
        ip_len = IP6_LENGTH;
        break;
    default:
        fprintf(stderr, "IP version %d is not supported now\n", buff[1]);
        return -1;
    }

    cur += FC_HDR_BM_FIX_LENGTH;
    memcpy(&bm, buff, cur);

    bm.src_ip_num = ntohs(bm.src_ip_num);
    bm.dst_ip_num = ntohs(bm.dst_ip_num);
    bm.fc_num = ntohs(bm.fc_num);
    bm.siglen = ntohs(bm.siglen);
    bm.local_asn = ntohl(bm.local_asn);
    bm.version = ntohl(bm.version);
    bm.subversion = ntohl(bm.subversion);

    // src_ip
    for (i = 0; i < bm.src_ip_num; ++i)
    {
        bm.src_ip[i].prefix_length = *(buff + cur + ip_len);
        switch (bm.ipversion)
        {
        case IPV4:
            struct sockaddr_in *in4 = (struct sockaddr_in *)&bm.src_ip[i].ip;
            in4->sin_family = AF_INET;
            memcpy(&(in4->sin_addr), buff + cur, ip_len);
            //    in4->sin_addr.s_addr = ntohl(in4->sin_addr.s_addr);
            break;
        case IPV6:
            struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)&bm.src_ip[i].ip;
            in6->sin6_family = AF_INET6;
            memcpy(&(in6->sin6_addr), buff + cur, ip_len);
            break;
        default:
            break;
        }
        cur += ip_len + 1;
    }

    // dst_ip
    for (i = 0; i < bm.dst_ip_num; ++i)
    {
        bm.dst_ip[i].prefix_length = *(buff + cur + ip_len);
        switch (bm.ipversion)
        {
        case IPV4:
            struct sockaddr_in *in4 = (struct sockaddr_in *)&bm.dst_ip[i].ip;
            in4->sin_family = AF_INET;
            memcpy(&(in4->sin_addr), buff + cur, ip_len);
            //   in4->sin_addr.s_addr = ntohl(in4->sin_addr.s_addr);
            break;
        case IPV6:
            struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)&bm.dst_ip[i].ip;
            memcpy(&(in6->sin6_addr), buff + cur, ip_len);
            break;
        default:
            break;
        }
        cur += ip_len + 1;
    }

    // fclist
    for (i = 0; i < bm.fc_num; ++i)
    {
        u16 siglen = 0;
        u32 asn = 0;
        // pasn
        memcpy(&asn, buff + cur, sizeof(u32));
        cur += sizeof(u32);
        bm.fclist[i].previous_asn = ntohl(asn);
        // casn
        memcpy(&asn, buff + cur, sizeof(u32));
        cur += sizeof(u32);
        bm.fclist[i].current_asn = ntohl(asn);
        // nasn
        memcpy(&asn, buff + cur, sizeof(u32));
        cur += sizeof(u32);
        bm.fclist[i].nexthop_asn = ntohl(asn);
        // ski
        memcpy(bm.fclist[i].ski, buff + cur, FC_SKI_LENGTH);
        cur += FC_SKI_LENGTH;
        // algo_id
        memcpy(&bm.fclist[i].algo_id, buff + cur, sizeof(u8));
        cur += sizeof(u8);
        // flags
        memcpy(&bm.fclist[i].flags, buff + cur, sizeof(u8));
        cur += sizeof(u8);
        // siglen
        memcpy(&siglen, buff + cur, sizeof(u16));
        cur += sizeof(u16);
        bm.fclist[i].siglen = ntohs(siglen);
        // sig
        memcpy(bm.fclist[i].sig, buff + cur, bm.fclist[i].siglen);
        cur += bm.fclist[i].siglen;

        if (bm.fclist[i].nexthop_asn == bm.fclist[i].previous_asn)
        {
            fprintf(stderr, "Not needed fclist, 3 asns: %08X %08X %08X\n",
                    bm.fclist[i].previous_asn,
                    bm.fclist[i].current_asn,
                    bm.fclist[i].nexthop_asn);
            return -1;
        }
    }

    ret = fc_bm_verify_fc(&bm);
    FC_ASSERT_RET(ret);

    // signature to be signed and verified
    // THIS is in network byte order
    memcpy(msg, buff, cur);

    if (msg_type == FC_MSG_BGPD)
    {
        // add signature for sending to peers
        printf("prikey_fname: %s\n", g_fc_server.prikey_fname);
        fc_ecdsa_sign(g_fc_server.prikey, msg, cur, &sigbuff, &sigbufflen);
        memcpy(buff + cur, g_fc_server.ski, FC_SKI_LENGTH);
        memcpy(bm.ski, g_fc_server.ski, FC_SKI_LENGTH);
        memcpy(buff + cur + FC_SKI_LENGTH, sigbuff, sigbufflen);
        bm.siglen = sigbufflen;
        sigbufflen = htons(sigbufflen);
        memcpy(&buff[FC_HDR_BM_SIGLEN_POS], &sigbufflen, sizeof(bm.siglen));
        memcpy(bm.signature, sigbuff, bm.siglen);
        OPENSSL_free(sigbuff);
        // broadcast to onpath nodes
        buff_new_msg[1] = FC_MSG_BC; // type: bc msg
        fc_bm_broadcast_to_peer(clisockfd, &bm, buff_new_msg,
                                FC_HDR_GENERAL_LENGTH + cur + FC_SKI_LENGTH + bm.siglen);
    }
    else if (msg_type == FC_MSG_BC)
    {
        // verify and remove signature
        // SIGLEN MUST be 0 when verify SIGNATURE
        memset(&msg[FC_HDR_BM_SIGLEN_POS], 0, sizeof(16));
        memcpy(bm.ski, buff + cur, FC_SKI_LENGTH);
        memcpy(bm.signature, buff + cur + FC_SKI_LENGTH, bm.siglen);

        /* TODO Don't know why does not need this pubkey. */
#if 0
        FC_ht_node_as_t *node;
        FC_node_as_t meta = {0};
        meta.asn = bm.local_asn;
        node = htbl_meta_find(&g_fc_server.ht_as, &meta);
        printf("g_fc_server.local_asn: %u, bm.local_asn: %u, node.asn: %u\n",
               g_fc_server.local_asn, bm.local_asn, node->asn);
        printf("g_fc_server.ski: ");
        for (int k = 0; k < FC_SKI_LENGTH; ++k)
        {
            printf("%02X", g_fc_server.ski[k]);
        }
        printf("\n");
        printf("bm.ski: ");
        for (int k = 0; k < FC_SKI_LENGTH; ++k)
        {
            printf("%02X", bm.ski[k]);
        }
        printf("\n");
        printf("node.ski: ");
        for (int k = 0; k < FC_SKI_LENGTH; ++k)
        {
            printf("%02X", node->ski[k]);
        }
        printf("\n");
#endif

        // ret = fc_ecdsa_verify(node->pubkey,
        ret = fc_ecdsa_verify(g_fc_server.pubkey,
                              msg, cur, bm.signature, bm.siglen);
        switch (ret)
        {
        case 1:
            printf("verify sig ok\n");
            break;
        case 0:
            printf("verify sig failed\n");
            break;
        default:
            printf("verify sig error\n");
            break;
        }
    }

    fc_bm_print(&bm);
    fc_gen_acl(clisockfd, &bm);
    fc_db_write_bm(&bm);

    return 0;
}

int fc_server_handler(int clisockfd, char *buff, int buffsize, int recvlen)
{
    printf("\033[35m### Process One Packet Start ###\n\033[0m");
   
    int bufflen = 0;
    // for (int i = 0; i < recvlen; i++)
    // {
    //     printf("\033[5m%02X", (uint8_t)buff[i]);
    // }
    // printf("\033[0m");

    memcpy(&bufflen, &buff[2], sizeof(u16));
    bufflen = ntohs(bufflen);
    printf("bufflen: %d, recvlen: %d, fc-version: %d\n",
           bufflen, recvlen, buff[0]);

    if (buff[0] == FC_VERSION)
    {
        switch (buff[1])
        {
        case FC_MSG_PUBKEY: // pubkey
            printf("Not support pubkey\n");
            fc_server_pubkey_handler(clisockfd, buff, recvlen);
            return 0;
        case FC_MSG_BGPD: // bm
            fc_server_bm_handler(clisockfd, buff, recvlen, FC_MSG_BGPD);
            break;
        case FC_MSG_BC: // broadcast msg
            fc_server_bm_handler(clisockfd, buff, recvlen, FC_MSG_BC);
            break;
        case FC_MSG_TOPO:
            fc_server_topo_handler(clisockfd, buff, recvlen);
            break;
        default:
            printf("Not support %d\n", buff[0]);
            return -1;
        }
    }
    else
    {
        printf("recvlen: %d\n", recvlen);
        if (recvlen > 1)
        {
            printf("FC HDR VERSION: %d\n", buff[0]);
        }
    }
    printf("\033[35m### Process One Packet End ###\n\033[0m");

    return 0;
}

static inline int
print_line(char ch, char *string)
{

    int i = 0, line_len = 78, ln = 0, rn = 0, string_len = 0;

    string_len = strlen(string);
    ln = (line_len - string_len) / 2;
    rn = line_len - string_len - ln;

    printf("*");
    for (i = 0; i < ln; ++i)
        printf("%c", ch);
    printf("%s", string);
    for (i = 0; i < rn; ++i)
        printf("%c", ch);
    printf("*\n");

    return 0;
}

static inline void
fc_welcome_banner()
{
    print_line('*', "");
    print_line(' ', FC_VERSION_STR);
    print_line(' ', "Home page: <https://gitee.com/basil1728/fcbgp-new>");
    print_line(' ', "A private repository. Not avaliable without permission.");
    print_line(' ', "Need help or report bugs please mailto: guoyangfei@zgclab.edu.cn");
    print_line(' ', "SSL_VERSION: " FC_SSL_VERSION);
    print_line('*', "");
}

static inline void
fc_help(void)
{
    fc_welcome_banner();
    printf("\n");
    printf("\t-f <config.json>  Specify the location of config.json.\n");
    printf("\t                   Default location is /etc/frr/assets/\n");
    printf("\t-h                 Print this message.\n");
    printf("\t-v                 Print FC Server version.\n");
}

static void
fc_parse_args(int argc, char **argv)
{
    int opt = 0;

    while ((opt = getopt(argc, argv, "f:hv")) > 0)
    {
        switch (opt)
        {
        case 'f':
            memcpy(g_fc_server.config_fname, optarg, strlen(optarg));
            break;
        case 'v':
            fc_welcome_banner();
            exit(EXIT_SUCCESS);
        case 'h':
            fc_help();
            exit(EXIT_SUCCESS);
        default:
            printf("unknown opt: %d\n", opt);
            fc_help();
            exit(EXIT_FAILURE);
        }
    }

    if (!g_fc_server.config_fname || strlen(g_fc_server.config_fname) == 0)
    {
        g_fc_server.config_fname = strdup(FC_CFG_DEFAULT_CONFIG_FNAME);
    }
}

int fc_main()
{
    int ret = 0;

    signal(SIGINT, fc_server_destroy);

    fc_welcome_banner();

    diag_init(g_fc_server.prog_name);

    fc_hashtable_create(&g_fc_server.ht_as, &g_fc_htbl_as_ops);

    // aclinfo ht
    ht_aclinfo_create(&g_fc_server.ht_aclinfo);

    fc_read_config();

    if (g_fc_server.log_level > FC_LOG_LEVEL_INFO)
    {
        htbl_display(&g_fc_server.ht_as);
    }

    diag_level_set(g_fc_server.log_level);

    fc_init_crypto_env(&g_fc_server);

    ret = fc_server_create();
    FC_ASSERT_RET(ret);

    return 0;
}

void fc_server_destroy(int signum)
{
    FC_router_info_t *router = NULL;

    if (signum == SIGINT || signum == SIGUSR1)
    {
        printf("recevied SIGINT\n");
        diag_fini();

        // close all routers
        fc_server_topo_del_all_routers();

        // close the advanced fcs if used
        if (g_fc_server.fc_bgpd_ctx6)
        {
            ncs6_manager_stop(g_fc_server.fc_bgpd_ctx6);
            ncs6_destroy(g_fc_server.fc_bgpd_ctx6);
            g_fc_server.fc_bgpd_ctx6 = NULL;
        }

        // close the low level fcs if used
        if (g_fc_server.sockfd)
        {
            close(g_fc_server.sockfd);
        }
        if (g_fc_server.epollfd)
        {
            close(g_fc_server.epollfd);
        }

        // close the db
        if (g_fc_server.db)
        {
            fc_db_close(g_fc_server.db);
            g_fc_server.db = NULL;
        }

        // close the ncclient session
        router = g_fc_server.routers;
        while (router)
        {
            py_teardown(&router->py_config);
            router = router->next;
        }

        fc_hashtable_destroy(&g_fc_server.ht_as);
        fc_hashtable_destroy(&g_fc_server.ht_prefix);
        ht_aclinfo_destroy(g_fc_server.ht_aclinfo);

        if (g_fc_server.pubkey)
        {
            EC_KEY_free(g_fc_server.pubkey);
            g_fc_server.pubkey = NULL;
        }

        if (g_fc_server.prikey)
        {
            EC_KEY_free(g_fc_server.prikey);
            g_fc_server.prikey = NULL;
        }

        FC_MEM_FREE(g_fc_server.prikey_fname);
        FC_MEM_FREE(g_fc_server.certs_location);
        FC_MEM_FREE(g_fc_server.config_fname);
        FC_MEM_FREE(g_fc_server.fc_db_fname);

        printf("bye bye!\n");
        exit(EXIT_SUCCESS);
    }
}

int main(int argc, char **argv)
{
    g_fc_server.prog_name = FC_PROGRAM_NAME;
    g_fc_server.prog_addr4 = "0.0.0.0";
    g_fc_server.prog_addr6 = "::";
    g_fc_server.config_fname = NULL;
    g_fc_server.prikey_fname = NULL;
    g_fc_server.certs_location = NULL;

    fc_parse_args(argc, argv);
    fc_main();

    return 0;
}
