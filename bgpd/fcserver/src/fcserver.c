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
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <openssl/opensslv.h>
#include <pthread.h>
#include <stdbool.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "dbutils.h"
#include "fcconfig.h"
#include "fcserver.h"
#include "hashutils.h"

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

#define fc_print_error(err_no)                   \
    do                                           \
    {                                            \
        DIAG_ERROR("[%s: %d] error: %s\n",       \
                   __func__, __LINE__,           \
                   fc_err_sock_strings[err_no]); \
    } while (0)

FC_server_t g_fc_server = {0};

int fc_sock_get_addr_from_peer_fd(int fd,
                                  struct sockaddr *sockaddr,
                                  char *ipbuf,
                                  int buffsize)
{
    int ret = 0;
    socklen_t socklen = sizeof(struct sockaddr);

    ret = getpeername(fd, sockaddr, &socklen);
    if (ret != 0)
    {
        DIAG_ERROR("getpeername(): %s\n", strerror(errno));
        return FC_ERR_SERVER_GPN;
    }

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
        DIAG_ERROR("socket(): %s\n", strerror(errno));
        return FC_ERR_SERVER_SOCK_SOCKET;
    }

    // set nonblock
    ret = fc_sock_set_nonblock(g_fc_server.sockfd);
    if (ret < 0)
    {
        DIAG_ERROR("fcntl(): %s\n", strerror(errno));
        return FC_ERR_SERVER_FCNTL;
    }

    // setsockopt reuse address
    ret = setsockopt(g_fc_server.sockfd, SOL_SOCKET, SO_REUSEADDR,
                     &yes, sizeof(int));
    if (ret == -1)
    {
        DIAG_ERROR("setsockopt(), %s\n", strerror(errno));
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
        DIAG_ERROR("bind(), %s\n", strerror(errno));
        return FC_ERR_SERVER_SOCK_BIND;
    }

    // listen
    ret = listen(g_fc_server.sockfd, FC_SOCK_BACKLOG);
    if (ret < 0)
    {
        DIAG_ERROR("listen(), %s\n", strerror(errno));
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
                DIAG_ERROR("accept(), %s\n", strerror(errno));
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
            DIAG_ERROR("epoll_ctl(), %s\n", strerror(errno));
            return FC_ERR_SERVER_EPOLL_CTL;
        }
        DIAG_INFO("New connection fd: %d\n", clisockfd);
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
                DIAG_ERROR("read(), %s\n", strerror(errno));
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
    DIAG_INFO("Recv from fd: %d, remote.addr: %s, remote.port: %d\n",
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
        DIAG_ERROR("epoll_create(), %s\n", strerror(errno));
        return FC_ERR_SERVER_EPOLL_CREATE;
    }

    // add server socket to epoll events
    event.data.fd = g_fc_server.sockfd;
    event.events = EPOLLIN | EPOLLET;
    ret = epoll_ctl(g_fc_server.epollfd, EPOLL_CTL_ADD,
                    g_fc_server.sockfd, &event);
    if (ret < 0)
    {
        DIAG_ERROR("epoll_ctl(), %s\n", strerror(errno));
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
                DIAG_ERROR("epoll error on fd: %d\n", events[i].data.fd);
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
                DIAG_INFO("fd: %d, recvlen: %d\n",
                          events[i].data.fd, recvlen);
                fc_server_handler(events[i].data.fd, buff, FC_BUFF_SIZE, recvlen);

                if (done)
                {
                    DIAG_INFO("Closed connection on fd: %d\n",
                              events[i].data.fd);
                    /* closing the descriptor will make epoll remove it
                     * from the set of fds which are monitored. */
                    close(events[i].data.fd);
                    DIAG_INFO("#################################################\n\n\n");
                }
            }
        }
    }

    free(events);

    return ret;
}

static inline void
fc_server_show_info(void)
{
    DIAG_INFO("program name: %s\n", g_fc_server.prog_name);
    DIAG_INFO("program address ipv4: %s\n", g_fc_server.prog_addr4);
    DIAG_INFO("program address ipv6: %s\n", g_fc_server.prog_addr6);
    DIAG_INFO("log level: %u\n", g_fc_server.log_level);
    DIAG_INFO("clear fc db: %d\n", g_fc_server.clear_fc_db);
    DIAG_INFO("user_data_plane: %d\n", g_fc_server.use_data_plane);
    DIAG_INFO("local asn: %u\n", g_fc_server.local_asn);
    DIAG_INFO("hash algorithm: %s\n", g_fc_server.hash_algorithm);
    DIAG_INFO("listen port: %d\n", g_fc_server.listen_port);
    DIAG_INFO("ASNs:\n");
    for (int i = 0; i < g_fc_server.asns_num; ++i)
    {
        DIAG_INFO("  asn: %u\n", g_fc_server.asns[i]);
    }
    DIAG_INFO("db file name: %s\n", g_fc_server.fc_db_fname);
    DIAG_INFO("config file name: %s\n", g_fc_server.config_fname);
    DIAG_INFO("prikey file name: %s\n", g_fc_server.prikey_fname);
    DIAG_INFO("certs location: %s\n", g_fc_server.certs_location);
    fc_print_bin("local ski", g_fc_server.ski, FC_SKI_LENGTH);
    DIAG_INFO("NICs:\n");
    for (int i = 0; i < g_fc_server.nics_num; ++i)
    {
        DIAG_INFO(" nic: %s\n", g_fc_server.nics[i]);
    }
}

static int
fc_multi_long_pull_server(void)
{
    int ret = 0;

    fc_server_show_info();

    /* socket */
    ret = fc_mlp_server_sock();
    if (ret < 0)
    {
        fc_print_error(ret);
        goto atexit;
    }

    DIAG_INFO("FCServer in AS %d is ready!!!\n", g_fc_server.local_asn);

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

    int ret = fc_multi_long_pull_server();

    return ret;
}

bool fc_asn_is_offpath(u32 asn, const FC_msg_bm_t *bm)
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

int fc_server_handler(int clisockfd, char *buff, int buffsize, int recvlen)
{
    int currlen = 0;
    int i = 0;

    // many messages may be stuck.
    while (currlen < recvlen)
    {
        i++;
        DIAG_INFO("### Process Packet: %d Start ###\n", i);

        u8 fc_msg_version = buff[currlen];
        u8 fc_msg_type = buff[currlen + 1];
        u16 fc_msg_len = 0;
        memcpy(&fc_msg_len, &buff[currlen + 2], sizeof(u16));
        fc_msg_len = ntohs(fc_msg_len);

        DIAG_INFO("packet index: %d, recvlen: %d, currlen: %d, "
                  "fc-version: %d, fc-type: %d, fc-msglen: %d\n",
                  i, recvlen, currlen, fc_msg_version, fc_msg_type, fc_msg_len);

        if (fc_msg_version != FC_MSG_VERSION)
        {
            DIAG_ERROR("WRONG FC HDR VERSION: %d\n", fc_msg_version);
            currlen = currlen + FC_HDR_GENERAL_LENGTH + fc_msg_len;
            continue;
        }

        unsigned char msg[BUFSIZ] = {0};
        int msglen = fc_msg_len + FC_HDR_GENERAL_LENGTH;
        memcpy(msg, buff + currlen, msglen); // including general header
        fc_print_bin("new packet", msg + currlen, FC_HDR_GENERAL_LENGTH + fc_msg_len);
        currlen = currlen + FC_HDR_GENERAL_LENGTH + fc_msg_len;

        switch (fc_msg_type)
        {
        case FC_MSG_PUBKEY: // pubkey
            DIAG_ERROR("Not support pubkey\n");
            fc_server_pubkey_handler(clisockfd, msg, msglen);
            break;
        case FC_MSG_BGPD: // bm
            fc_server_bm_handler(clisockfd, msg, msglen, FC_MSG_BGPD);
            break;
        case FC_MSG_BC: // broadcast msg
            fc_server_bm_handler(clisockfd, msg, msglen, FC_MSG_BC);
            break;
        case FC_MSG_TOPO:
            fc_server_topo_handler(clisockfd, msg, msglen);
            fc_server_topo_init_msg(clisockfd);
            break;
        default:
            DIAG_ERROR("Not supported message type: %d\n", fc_msg_type);
            break;
        }

        DIAG_INFO("### Process Packet: %d End ###\n", i);
    }

    return 0;
}

static inline void
fc_server_info_welcome_banner(void)
{
    fc_cmd_version();
}

void fc_server_info_help(void)
{
    fc_server_info_welcome_banner();
    fprintf(stdout, "\n");
    fprintf(stdout, "\t-f <config.json>  Specify the location of config.json.\n");
    fprintf(stdout, "\t                  Default location is /etc/frr/assets/\n");
    fprintf(stdout, "\t-h                Print this message.\n");
    fprintf(stdout, "\t-v                Print FC Server version.\n");
}

static void
fc_server_args_parse(int argc, char **argv)
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
            fc_server_info_welcome_banner();
            exit(EXIT_SUCCESS);
        case 'h':
            fc_server_info_help();
            exit(EXIT_SUCCESS);
        default:
            DIAG_ERROR("unknown opt: %d\n", opt);
            fc_server_info_help();
            exit(EXIT_FAILURE);
        }
    }

    if (!g_fc_server.config_fname || strlen(g_fc_server.config_fname) == 0)
    {
        g_fc_server.config_fname = strdup(FC_CFG_DEFAULT_CONFIG_FNAME);
    }
}

void *fc_server_main_backend(void *args)
{
    (void)args;
    int ret = 0;

    signal(SIGINT, fc_server_destroy);

    fc_server_info_welcome_banner();

    diag_init(g_fc_server.prog_name);

    fc_hashtable_create(&g_fc_server.ht_as, &g_fc_htbl_as_ops);

    // aclinfo ht

    ht_aclinfo_create(&g_fc_server.ht_acl_group_info);

    fc_read_config();

    if (g_fc_server.log_level > FC_LOG_LEVEL_INFO)
    {
        htbl_display(&g_fc_server.ht_as);
    }

    diag_level_set(g_fc_server.log_level);

    ret = fc_server_create();
    FC_ASSERT_RET(ret);

    return NULL;
}

void fc_server_destroy(int signum)
{
    FC_router_info_t *router = NULL;

    if (signum == SIGINT || signum == SIGUSR1)
    {
        DIAG_INFO("recevied signal: %d\n", signum);
        diag_fini();

        // close all routers
        fc_server_topo_del_all_routers();

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
        ht_aclinfo_destroy(g_fc_server.ht_acl_group_info);

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

        DIAG_INFO("bye bye~\n");
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

    fc_server_args_parse(argc, argv);

    pthread_t tid, ret = 0;
    ret = pthread_create(&tid, NULL, fc_server_main_backend, NULL);
    if (ret < 0)
    {
        DIAG_ERROR("pthread_create failed, %s\n", strerror(errno));
        return 1;
    }
    pthread_detach(tid);

    // as we only read from g_fc_server,
    // so it is not necessary to use pthread_mutex
    fc_main_front(NULL);

    return 0;
}
