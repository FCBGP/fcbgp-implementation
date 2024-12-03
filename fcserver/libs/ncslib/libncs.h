#ifndef _LIBNCS_H_
#define _LIBNCS_H_

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
typedef struct ncs_ctx_st
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
    struct sockaddr client_peeraddr;
    struct sockaddr server_peeraddr;

    uint16_t remote_port;
    uint16_t local_port;

    char remote_addr[32];
    char local_addr[32];

    mutex_t mutex;
    pthread_t server_tid;
    pthread_t manager_tid;

    int (*server_handler)(struct ncs_ctx_st* ctx);
} ncs_ctx_t;

extern int ncs_sock_create(int domain, int type, int protocol);
extern void ncs_sock_setblock(int fd);
extern void ncs_sock_setnonblock(int fd);
extern int ncs_sock_bind(int fd, struct sockaddr* addr, socklen_t len);
extern int ncs_sock_listen(int fd, int backlog);
extern void ncs_sock_shutdown(int fd, int how);
extern int ncs_sock_connect(int fd, struct sockaddr* addr, socklen_t len,
                            int timeout);
extern int ncs_sock_accept(int fd, struct sockaddr* addr, socklen_t* len,
                           int timeout);
extern int ncs_sock_send(int fd, void* data, int count, int* sent, int timeout);
extern int ncs_sock_sendto(int fd, void* data, int count, int* sent,
                           struct sockaddr* addr, socklen_t len, int timeout);
extern int ncs_sock_recv(int fd, void* data, int count, int* got, int timeout);
extern int ncs_sock_recvfrom(int fd, void* data, int count, int* got,
                             struct sockaddr* addr, socklen_t* len,
                             int timeout);
extern int ncs_buffer_send(int fd, void* data, int count, int* sent,
                           int timeout);
extern int ncs_buffer_recv(int fd, void* data, int count, int* got,
                           int timeout);
extern int ncs_client_connect(ncs_ctx_t* ctx);
extern int ncs_client_start(ncs_ctx_t* ctx);
extern int ncs_client_stop(ncs_ctx_t* ctx);
extern int ncs_manager_stop(ncs_ctx_t* ctx);
extern int ncs_manager_start(ncs_ctx_t* ctx);
extern ncs_ctx_t* ncs_create(char* name, int proto);
extern void ncs_destroy(ncs_ctx_t* ctx);
extern void ncs_mutex_lock(ncs_ctx_t* ctx);
extern void ncs_mutex_unlock(ncs_ctx_t* ctx);
extern int ncs_setup(ncs_ctx_t* ctx, char* local_addr, uint16_t local_port,
                     char* remote_addr, uint16_t remote_port);
extern int ncs_timeout(ncs_ctx_t* ctx, int recv_timeout, int send_timeout);
extern int ncs_setbuf(ncs_ctx_t* ctx, int rcvbuf, int sndbuf);
extern int ncs_setlinger(ncs_ctx_t* ctx, int linger);
extern int ncs_setkeepalive(ncs_ctx_t* ctx, int keepalive);
extern int ncs_client_enable(ncs_ctx_t* ctx);
extern int ncs_client_disable(ncs_ctx_t* ctx);
extern int ncs_server_enable(ncs_ctx_t* ctx);
extern int ncs_server_disable(ncs_ctx_t* ctx);
extern int ncs_client_send(ncs_ctx_t* ctx, char* data, int length);
extern int ncs_client_recv(ncs_ctx_t* ctx, char* data, int length);
extern int ncs_server_send(ncs_ctx_t* ctx, char* data, int length);
extern int ncs_server_recv(ncs_ctx_t* ctx, char* data, int length);
extern int ncs_server_register(ncs_ctx_t* ctx,
                               int (*server_handler)(struct ncs_ctx_st* ctx));

#endif
