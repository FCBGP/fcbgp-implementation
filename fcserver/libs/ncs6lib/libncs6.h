#ifndef _LIBNCS6_H_
#define _LIBNCS6_H_

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "libmutex.h"

/*
 * Network client and server context.
 */
typedef struct ncs6_ctx_st
{
    char* name;

    int client_enable : 1;
    int client_started : 1;
    int client_connected : 1;
    int server_enable : 1;
    int server_started : 1;
    int manager_running : 1;
    int manager_paused : 1;
    int clientinfo_changed : 1;
    int serverinfo_changed : 1;
    int keep_alive : 1;
    int is_valid : 1;
    int is_udp : 1;

    int server_sock;
    int server_connid;
    int client_sock;
    int recv_timeout;
    int send_timeout;
    int client_error;
    int server_error;
    int client_rcvbuf;
    int server_rcvbuf;
    int client_sndbuf;
    int server_sndbuf;
    int client_linger;
    int server_linger;

    /* for udp recvfrom and sendto. */
    socklen_t client_peerlen;
    socklen_t server_peerlen;
    struct sockaddr_in6 client_peeraddr;
    struct sockaddr_in6 server_peeraddr;

    uint16_t remote_port;
    uint16_t local_port;

    char remote_addr[128];
    char local_addr[128];

    mutex_t mutex;
    pthread_t server_tid;
    pthread_t manager_tid;

    int (*server_handler)(struct ncs6_ctx_st* ctx);
} ncs6_ctx_t;

extern int ncs6_sock_create(int domain, int type, int protocol);
extern void ncs6_sock_setblock(int fd);
extern void ncs6_sock_setnonblock(int fd);
extern int ncs6_sock_bind(int fd, struct sockaddr_in6* addr, socklen_t len);
extern int ncs6_sock_listen(int fd, int backlog);
extern void ncs6_sock_shutdown(int fd, int how);
extern int ncs6_sock_connect(int fd, struct sockaddr_in6* addr, socklen_t len,
                             int timeout);
extern int ncs6_sock_accept(int fd, struct sockaddr_in6* addr, socklen_t* len,
                            int timeout);
extern int ncs6_sock_send(int fd, void* data, int count, int* sent,
                          int timeout);
extern int ncs6_sock_sendto(int fd, void* data, int count, int* sent,
                            struct sockaddr_in6* addr, socklen_t len,
                            int timeout);
extern int ncs6_sock_recv(int fd, void* data, int count, int* got, int timeout);
extern int ncs6_sock_recvfrom(int fd, void* data, int count, int* got,
                              struct sockaddr_in6* addr, socklen_t* len,
                              int timeout);
extern int ncs6_buffer_send(int fd, void* data, int count, int* sent,
                            int timeout);
extern int ncs6_buffer_recv(int fd, void* data, int count, int* got,
                            int timeout);
extern int ncs6_client_connect(ncs6_ctx_t* ctx);
extern int ncs6_client_start(ncs6_ctx_t* ctx);
extern int ncs6_client_stop(ncs6_ctx_t* ctx);
extern int ncs6_manager_stop(ncs6_ctx_t* ctx);
extern int ncs6_manager_start(ncs6_ctx_t* ctx);
extern ncs6_ctx_t* ncs6_create(char* name, int proto);
extern void ncs6_destroy(ncs6_ctx_t* ctx);
extern void ncs6_mutex_lock(ncs6_ctx_t* ctx);
extern void ncs6_mutex_unlock(ncs6_ctx_t* ctx);
extern int ncs6_setup(ncs6_ctx_t* ctx, char* local_addr, uint16_t local_port,
                      char* remote_addr, uint16_t remote_port);
extern int ncs6_timeout(ncs6_ctx_t* ctx, int recv_timeout, int send_timeout);
extern int ncs6_setbuf(ncs6_ctx_t* ctx, int rcvbuf, int sndbuf);
extern int ncs6_setlinger(ncs6_ctx_t* ctx, int linger);
extern int ncs6_setkeepalive(ncs6_ctx_t* ctx, int keepalive);
extern int ncs6_client_enable(ncs6_ctx_t* ctx);
extern int ncs6_client_disable(ncs6_ctx_t* ctx);
extern int ncs6_server_enable(ncs6_ctx_t* ctx);
extern int ncs6_server_disable(ncs6_ctx_t* ctx);
extern int ncs6_client_send(ncs6_ctx_t* ctx, char* data, int length);
extern int ncs6_client_recv(ncs6_ctx_t* ctx, char* data, int length);
extern int ncs6_server_send(ncs6_ctx_t* ctx, char* data, int length);
extern int ncs6_server_recv(ncs6_ctx_t* ctx, char* data, int length);
extern int ncs6_server_register(ncs6_ctx_t* ctx,
                                int (*server_handler)(struct ncs6_ctx_st* ctx));
extern int get_linklocal_ipv6addr(char* addr6, char* iface);

#endif
