#include "libncs.h"
#include "libdiag.h"
#include "libendian.h"

#ifdef PRJ_SUPPORT_POLL
#include <sys/poll.h>

#define WAITFD_R POLLIN
#define WAITFD_W POLLOUT
#define WAITFD_C (POLLIN|POLLOUT)

static int ncs_sock_waitfd(int fd, int sw, int timeout)
{
    int ret;
    struct pollfd pfd;

    pfd.fd = fd;
    pfd.events = sw;
    pfd.revents = 0;

    if (timeout == 0) {
        return -ETIMEDOUT;
    }

    do {
        ret = poll(&pfd, 1, timeout);
    } while (ret == -1 && errno == EINTR);

    if (ret == -1) return -errno;
    if (ret == 0) return -ETIMEDOUT;
    if (sw == WAITFD_C && (pfd.revents & (POLLIN|POLLERR))) return -ESHUTDOWN;

    return 0;
}

#else

#define WAITFD_R 1
#define WAITFD_W 2
#define WAITFD_C (WAITFD_R|WAITFD_W)

static int ncs_sock_waitfd(int fd, int sw, int timeout)
{
    int ret;
    struct timeval tv, *tp;
    fd_set rfds, wfds, *rp, *wp;

    if (fd >= FD_SETSIZE) {
        return -EBADFD;
    }

    if (timeout == 0) {
        return -ETIMEDOUT;
    }

    do {
        rp = wp = NULL;

        if (sw & WAITFD_R) {
            FD_ZERO(&rfds);
            FD_SET(fd, &rfds);
            rp = &rfds;
        }

        if (sw & WAITFD_W) {
            FD_ZERO(&wfds);
            FD_SET(fd, &wfds);
            wp = &wfds;
        }

        tp = NULL;
        if (timeout > 0) {
            tv.tv_sec = (int)(timeout / 1000);
            tv.tv_usec = (int)(timeout % 1000) * 1000;
            tp = &tv;
        }

        ret = select(fd+1, rp, wp, NULL, tp);
    } while (ret == -1 && errno == EINTR);

    if (ret == -1) return -errno;
    if (ret == 0) return -ETIMEDOUT;
    if (sw == WAITFD_C && FD_ISSET(fd, &rfds)) return -ESHUTDOWN;

    return 0;
}
#endif

int ncs_sock_create(int domain, int type, int protocol)
{
    int fd = socket(domain, type, protocol);
    if (fd < 0) {
        return -errno;
    }

    return fd;
}

void ncs_sock_setblock(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    flags &= (~(O_NONBLOCK));
    fcntl(fd, F_SETFL, flags);
}

void ncs_sock_setnonblock(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    flags |= O_NONBLOCK;
    fcntl(fd, F_SETFL, flags);
}

int ncs_sock_bind(int fd, struct sockaddr *addr, socklen_t len)
{
    int err = 0;

    ncs_sock_setblock(fd);
    if (bind(fd, addr, len) < 0){
        err = -errno;
    }

    ncs_sock_setnonblock(fd);
    return err;
}

int ncs_sock_listen(int fd, int backlog)
{
    int err = 0;

    ncs_sock_setblock(fd);
    if (listen(fd, backlog)) {
        err = -errno;
    }

    ncs_sock_setnonblock(fd);
    return err;
}

void ncs_sock_shutdown(int fd, int how)
{
    ncs_sock_setblock(fd);
    shutdown(fd, how);
    ncs_sock_setnonblock(fd);
    close(fd);
}

int ncs_sock_connect(int fd, struct sockaddr *addr, socklen_t len, int timeout)
{
    int ret = -1;
    int errcode = 0;

    if (fd < 0) {
        return -EBADFD;
    }

    /* call connect until done or failed without being interrupted */
    while (1) {
        if (connect(fd, addr, len) == 0) {
            return 0;
        }

        errcode = errno;
        if (errcode != EINTR) {
            break;
        }
    }

    /* if connection failed immediately, return error code */
    if (errcode != EINPROGRESS && errcode != EAGAIN) {
        return -errcode;
    }

    /* zero timeout case optimization */
    if (timeout == 0) {
        return -ETIMEDOUT;
    }

    /* wait until we have the result of the connection attempt or timeout */
    ret = ncs_sock_waitfd(fd, WAITFD_C, timeout);
    if (ret == -ESHUTDOWN) {
        if (recv(fd, (char *) &errcode, 0, 0) == 0) {
            return 0;
        } else {
            return -errno;
        }
    }

    return ret;
}

int ncs_sock_accept(int fd, struct sockaddr *addr, socklen_t *len, int timeout)
{
    int ret= -1;
    int errcode = 0;

    if (fd < 0) {
        return -EBADFD;
    }

    while (1) {
        ret = accept(fd, addr, len);
        if (ret < 0) {
            errcode = errno;
            if (errcode == EINTR) {
                continue;
            }

            if (errcode != EAGAIN && errcode != ECONNABORTED) {
                return -errcode;
            }

            ret = ncs_sock_waitfd(fd, WAITFD_R, timeout);
            if (ret != 0) {
                return ret;
            }
        }

        return ret;
    }

    /* can't reach here */
    return -EINVAL;
}

int ncs_sock_send(int fd, void *data, int count, int *sent, int timeout)
{
    int ret = -1;
    int errcode = 0;

    *sent = 0;
    if (fd < 0) {
        return -EBADFD;
    }

    while (1) {
        int txlen = send(fd, data, count, 0);
        if (txlen >= 0) {
            *sent = txlen;
            return 0;
        }

        errcode = errno;
        /* we call was interrupted, just try again */
        if (errcode == EINTR) {
            continue;
        }

        /* EPIPE means the connection was closed */
        if (errcode == EPIPE) {
            return -ESHUTDOWN;
        }

        /* if failed fatal reason, report error */
        if (errcode != EAGAIN) {
            return -errcode;
        }

        /* wait until we can send something or we timeout */
        ret = ncs_sock_waitfd(fd, WAITFD_W, timeout);
        if (ret != 0) {
            return ret;
        }
    }

    /* can't reach here */
    return -EINVAL;
}

int ncs_sock_sendto(int fd, void *data, int count, int *sent, struct sockaddr *addr, socklen_t len, int timeout)
{
    int ret = -1;
    int errcode = 0;

    *sent = 0;
    if (fd < 0) {
        return -EBADFD;
    }

    while (1) {
        int txlen = sendto(fd, data, count, 0, addr, len);
        if (txlen >= 0) {
            *sent = txlen;
            return 0;
        }

        errcode = errno;
        /* we call was interrupted, just try again */
        if (errcode == EINTR) {
            continue;
        }

        /* EPIPE means the connection was closed */
        if (errcode == EPIPE) {
            return -ESHUTDOWN;
        }

        /* if failed fatal reason, report error */
        if (errcode != EAGAIN) {
            return -errcode;
        }

        ret = ncs_sock_waitfd(fd, WAITFD_W, timeout);
        if (ret != 0) {
            return ret;
        }
    }

    return -EINVAL;
}

int ncs_sock_recv(int fd, void *data, int count, int *got, int timeout)
{
    int ret = -1;
    int errcode = 0;

    *got = 0;
    if (fd < 0) {
        return -EBADFD;
    }

    while (1) {
        int rxlen = recv(fd, data, count, 0);
        if (rxlen > 0) {
            *got = rxlen;
            return 0;
        }

        errcode = errno;
        if (rxlen == 0) {
            return -ESHUTDOWN;
        }

        /* we call was interrupted, just try again */
        if (errcode == EINTR) {
            continue;
        }

        /* if failed fatal reason, report error */
        if (errcode != EAGAIN) {
            return -errcode;
        }

        /* wait until we can recv something or we timeout */
        ret = ncs_sock_waitfd(fd, WAITFD_R, timeout);
        if (ret != 0) {
            return ret;
        }
    }

    return -EINVAL;
}

int ncs_sock_recvfrom(int fd, void *data, int count, int *got, struct sockaddr *addr, socklen_t *len, int timeout)
{
    int ret = -1;
    int errcode = 0;

    *got = 0;
    if (fd < 0) {
       return -EBADFD;
    }

    while (1) {
        int rxlen = recvfrom(fd, data, count, 0, addr, len);
        if (rxlen > 0) {
            *got = rxlen;
            return 0;
        }

        errcode = errno;
        if (rxlen == 0) {
            return -ESHUTDOWN;
        }

        /* we call was interrupted, just try again */
        if (errcode == EINTR) {
            continue;
        }

        /* if failed fatal reason, report error */
        if (errcode != EAGAIN) {
            return -errcode;
        }

        /* wait until we can recv something or we timeout */
        ret = ncs_sock_waitfd(fd, WAITFD_R, timeout);
        if (ret != 0) {
            return ret;
        }
    }

    return -EINVAL;
}

int ncs_buffer_send(int fd, void *data, int count, int *sent, int timeout)
{
    int ret = -1;
    int txcnt = 0;
    int txlen = 0;
    int leftlen = count;
    char *dataptr = data;

    *sent = 0;
    while (leftlen > 0) {
        ret = ncs_sock_send(fd, dataptr, leftlen, &txlen, timeout);
        if (ret < 0) {
            *sent = txcnt;
            return ret;
        }

        txcnt += txlen;
        leftlen -= txlen;
        dataptr += txlen;
    }

    *sent = txcnt;
    return 0;
}

int ncs_buffer_sendto(int fd, void *data, int count, int *sent, struct sockaddr *addr, socklen_t len, int timeout)
{
    int ret = -1;
    int txcnt = 0;
    int txlen = 0;
    int leftlen = count;
    char *dataptr = data;

    *sent = 0;
    while (leftlen > 0) {
        ret = ncs_sock_sendto(fd, dataptr, leftlen, &txlen, addr, len, timeout);
        if (ret < 0) {
            *sent = txcnt;
            return ret;
        }

        txcnt += txlen;
        leftlen -= txlen;
        dataptr += txlen;
    }

    *sent = txcnt;
    return 0;
}

int ncs_buffer_recv(int fd, void *data, int count, int *got, int timeout)
{
    int ret = -1;
    int rxlen = 0;
    int rxcnt = 0;
    int leftlen = count;
    char *dataptr = data;

    *got = 0;
    while (leftlen > 0) {
        ret = ncs_sock_recv(fd, dataptr, leftlen, &rxlen, timeout);
        if (ret < 0) {
            *got = rxcnt;
            return ret;
        }

        rxcnt += rxlen;
        leftlen -= rxlen;
        dataptr += rxlen;
    }

    *got = rxcnt;
    return 0;
}

int ncs_buffer_recvfrom(int fd, void *data, int count, int *got, struct sockaddr *addr, socklen_t *len, int timeout)
{
    int ret = -1;
    int rxlen = 0;
    int rxcnt = 0;
    int leftlen = count;
    char *dataptr = data;

    *got = 0;
    while (leftlen > 0) {
        ret = ncs_sock_recvfrom(fd, dataptr, leftlen, &rxlen, addr, len, timeout);
        if (ret < 0) {
            *got = rxcnt;
            return ret;
        }

        rxcnt += rxlen;
        leftlen -= rxlen;
        dataptr += rxlen;
    }

    *got = rxcnt;
    return 0;
}

static int ncs_server_fini(ncs_ctx_t *ctx)
{
    if (ctx->server_sock != -1) {
        ncs_sock_shutdown(ctx->server_sock, SHUT_RDWR);
        ctx->server_sock = -1;
    }

    return 0;
}

static int ncs_server_init(ncs_ctx_t *ctx)
{
    int ret;
    int opt = 1;
    struct sockaddr_in server_sockaddr;

    if (ctx->local_addr[0] == '\0' || ctx->local_port == 0) {
        DIAG_ERROR("ncs %s server conninfo are invalid.\n", ctx->name);
        return -EINVAL;
    }

    memset(&server_sockaddr, 0, sizeof(struct sockaddr_in));
    server_sockaddr.sin_family = AF_INET;
    server_sockaddr.sin_addr.s_addr = inet_addr(ctx->local_addr);
    server_sockaddr.sin_port = htons(ctx->local_port);

    ctx->server_sock = ncs_sock_create(PF_INET, ctx->is_udp ? SOCK_DGRAM : SOCK_STREAM, 0);
    if (ctx->server_sock < 0) {
        DIAG_ERROR("ncs %s create server socket failed: %m\n", ctx->name);
        return ctx->server_sock;
    }

    setsockopt(ctx->server_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    setsockopt(ctx->server_sock, SOL_SOCKET, SO_RCVBUF, (const char *) &ctx->server_rcvbuf, sizeof(int));
    setsockopt(ctx->server_sock, SOL_SOCKET, SO_SNDBUF, (const char *) &ctx->server_sndbuf, sizeof(int));

    ncs_sock_setnonblock(ctx->server_sock);

    if (ctx->server_linger && !ctx->is_udp) {
        struct linger sl;
        sl.l_onoff = 1;
        sl.l_linger = ctx->server_linger;
        setsockopt(ctx->server_sock, SOL_SOCKET, SO_LINGER, (const char *) &sl, sizeof(struct linger));
    }

    DIAG_PRINT("ncs %s server try to bind %s:%d\n", ctx->name, ctx->local_addr, ctx->local_port);
    ret = ncs_sock_bind(ctx->server_sock, (struct sockaddr *)&server_sockaddr, sizeof(struct sockaddr_in));
    if (ret != 0) {
        DIAG_ERROR("ncs %s bind server socket failed: %m\n", ctx->name);
        ncs_server_fini(ctx);
        return ret;
    }

    if (!ctx->is_udp) {
        ret = ncs_sock_listen(ctx->server_sock, 32);
        if (ret != 0) {
            DIAG_ERROR("ncs %s listen server socket failed: %m\n", ctx->name);
            ncs_server_fini(ctx);
            return ret;
        }
    }

    signal(SIGPIPE, SIG_IGN);
    return 0;
}

static int ncs_client_fini(ncs_ctx_t *ctx)
{
    if (ctx->client_sock != -1) {
        ncs_sock_shutdown(ctx->client_sock, SHUT_RDWR);
        ctx->client_sock = -1;
    }

    return 0;
}

static int ncs_client_init(ncs_ctx_t *ctx)
{
    int opt = 1;
    struct sockaddr_in client_addr = {0, };

    client_addr.sin_family = AF_INET;
    client_addr.sin_addr.s_addr = inet_addr(ctx->local_addr);
    client_addr.sin_port = htons(0);

    ctx->client_sock = socket(PF_INET, ctx->is_udp ? SOCK_DGRAM : SOCK_STREAM, 0);
    if (ctx->client_sock < 0) {
        DIAG_ERROR("ncs %s client socket create failed: %m\n", ctx->name);
        return -ENOTSOCK;
    }

    setsockopt(ctx->client_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    setsockopt(ctx->client_sock, SOL_SOCKET, SO_RCVBUF, (const char *) &ctx->client_rcvbuf, sizeof(int));
    setsockopt(ctx->client_sock, SOL_SOCKET, SO_SNDBUF, (const char *) &ctx->client_sndbuf, sizeof(int));

    ncs_sock_setnonblock(ctx->client_sock);

    if (ctx->server_linger && !ctx->is_udp) {
        struct linger cl;
        cl.l_onoff = 1;
        cl.l_linger = ctx->client_linger;
        setsockopt(ctx->client_sock, SOL_SOCKET, SO_LINGER, (const char *) &cl, sizeof(struct linger));
    }

    if (bind(ctx->client_sock, (struct sockaddr *) &client_addr, sizeof(client_addr))) {
        DIAG_ERROR("ncs %s client bind %s failed: %m\n", ctx->name, ctx->local_addr);
        ncs_client_fini(ctx);
        return -EADDRINUSE;
    }

    ctx->client_started = 1;
    return 0;
}

int ncs_client_connect(ncs_ctx_t *ctx)
{
    int ret;
    struct sockaddr_in server_addr = {0, };

    if (!ctx->client_started)
        return -ENOLINK;

    if (ctx->client_connected) {
        return 0;
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(ctx->remote_addr);
    server_addr.sin_port = htons(ctx->remote_port);
    socklen_t server_addr_length = sizeof(struct sockaddr_in);

    if (ctx->is_udp) {
        ctx->client_connected = 1;
        ctx->client_peerlen = server_addr_length;
        memcpy(&ctx->client_peeraddr, &server_addr, sizeof(struct sockaddr_in));
        return 0;
    }

    ret = ncs_sock_connect(ctx->client_sock, (struct sockaddr *) &server_addr, server_addr_length, ctx->recv_timeout);
    if (ret < 0) {
        DIAG_ERROR("ncs %s client connect %s:%d failed: %m\n", ctx->name, ctx->remote_addr, ctx->remote_port);
        return ret;
    }

    DIAG_PRINT("ncs %s client connect to %s:%d.\n", ctx->name, ctx->remote_addr, ctx->remote_port);
    ctx->client_connected = 1;
    return 0;
}

int ncs_client_start(ncs_ctx_t *ctx)
{
    if (!ctx->client_enable) {
        DIAG_ERROR("ncs %s client was disable.\n", ctx->name);
        return -ENOLINK;
    }

    if (ctx->client_started) {
        DIAG_WARNING("ncs %s client was running.\n", ctx->name);
        return 0;
    }

    ctx->client_error = 0;
    return ncs_client_init(ctx);
}

int ncs_client_stop(ncs_ctx_t *ctx)
{
    if (ctx->keep_alive) {
        return 0;
    }

    ncs_client_fini(ctx);
    ctx->client_started = 0;
    ctx->client_connected = 0;
    return 0;
}

static void ncs_server_cleanup(void *arg)
{
    ncs_ctx_t *ctx = arg;
    ncs_server_fini(ctx);
    if (ctx->server_connid >= 0) {
        ncs_sock_shutdown(ctx->server_connid, SHUT_RDWR);
        ctx->server_connid = -1;
    }
}

static void *ncs_server_process(void *arg)
{
    int ret;
    ncs_ctx_t *ctx = arg;
    struct sockaddr_in cliaddr;
    socklen_t length = sizeof(struct sockaddr_in);

    ret = ncs_server_init(ctx);
    if (ret < 0) {
        return NULL;
    }

    ctx->server_started = 1;
    pthread_cleanup_push(ncs_server_cleanup, arg);

    while (1) {
        pthread_testcancel();

        /* wait until we can recv something or we timeout */
        ret = ncs_sock_waitfd(ctx->server_sock, WAITFD_R, 1000);
        if (ret != 0) {
            continue;
        }

        if (!ctx->is_udp) {
            DIAG_PRINT("ncs %s server try accept %d...\n", ctx->name, ctx->server_sock);
            ctx->server_connid = ncs_sock_accept(ctx->server_sock, (struct sockaddr *)&cliaddr, &length, ctx->recv_timeout);
            if (ctx->server_connid < 0) {
                DIAG_ERROR("ncs %s socket accept failed: %m\n", ctx->name);
                continue;
            }

            ncs_sock_setnonblock(ctx->server_connid);
        } else {
            ctx->server_connid = ctx->server_sock;
        }

        ctx->server_error = 0;
        if (ctx->server_handler) {
            DIAG_PRINT("ncs %s server will handler new connid %d.\n", ctx->name, ctx->server_connid);
            ctx->server_handler(ctx);
        }

        if (!ctx->is_udp) {
            ncs_sock_shutdown(ctx->server_connid, SHUT_RDWR);
            ctx->server_connid = -1;
        }
    }

    pthread_cleanup_pop(1);
    return NULL;
}

static int ncs_server_start(ncs_ctx_t *ctx)
{
    int i = 0;
    if (ctx->server_started)
        return 0;

    if (pthread_create(&ctx->server_tid, NULL, (void *) ncs_server_process, ctx)) {
        DIAG_ERROR("ncs %s create server thread failed: %m\n", ctx->name);
        return -ECHILD;
    }

    // waiting for server thread call ncs_server_init done.
    while (i < 10000) {
        if (ctx->server_started) {
            DIAG_DEBUG("ncs %s server started.\n", ctx->name);
            return 0;
        }
        usleep(1000);
        i++;
    }

    return -ENOEXEC;
}

static int ncs_server_stop(ncs_ctx_t *ctx)
{
    pthread_cancel(ctx->server_tid);
    pthread_join(ctx->server_tid, NULL);
    ctx->server_started = 0;
    ctx->server_tid = -1;
    DIAG_DEBUG("ncs %s server stoped.\n", ctx->name);
    return 0;
}

static void *ncs_manager_handler(void *arg)
{
    int loop = 0;
    ncs_ctx_t *ctx = arg;

    ctx->manager_running = 1;
    while (1) {
        if (ctx->manager_running == 0) {
            DIAG_INFO("ncs %s manager thread exit...\n", ctx->name);
            break;
        }

        if (ctx->manager_paused) {
            sleep(1); // add sleep to avoid thread takes 100% cpu.
            continue;
        }

        if (ctx->serverinfo_changed) {
            if (ctx->server_started) {
                // stop the old server endpoint
                DIAG_DEBUG("ncs %s server existed, we will stop ncs server.\n", ctx->name);
                ncs_server_stop(ctx);
            }

            // start the new server endpoint
            if (ctx->server_enable) {
                DIAG_DEBUG("ncs %s server will start now.\n", ctx->name);
                ncs_server_start(ctx);
            }

            ctx->serverinfo_changed = 0;
        }

        if (ctx->server_enable) {
            if (ctx->server_started == 0) {
                if (loop % 120 == 0) {
                    DIAG_DEBUG("ncs %s server is not started, try again...\n", ctx->name);
                    ncs_server_start(ctx);
                }
            }
        }

        sleep(1); // add sleep to avoid thread takes 100% cpu.
        loop++;
    }

    if (ctx->server_started) {
        // stop the old server endpoint
        DIAG_DEBUG("ncs %s server exit...\n", ctx->name);
        ncs_server_stop(ctx);
    }

    return NULL;
}

int ncs_manager_stop(ncs_ctx_t *ctx)
{
    if (ctx == NULL) {
        return -EINVAL;
    }

    ctx->manager_paused = 1;
    return 0;
}

int ncs_manager_start(ncs_ctx_t *ctx)
{
    ctx->manager_paused = 0;
    return 0;
}

static int ncs_manager_init(ncs_ctx_t *ctx)
{
    int i = 0;

    if (ctx->manager_running)
        return 0;

    if (pthread_create(&ctx->manager_tid, NULL, (void *) ncs_manager_handler, (void *)ctx)) {
        DIAG_ERROR("ncs %s create manager thread failed: %m\n", ctx->name);
        return -ECHILD;
    }

    while (i < 10000) {
        if (ctx->manager_running) {
            DIAG_DEBUG("ncs %s manager start.\n", ctx->name);
            return 0;
        }
        usleep(1000);
        i++;
    }

    return -ENOEXEC;
}

static int ncs_manager_fini(ncs_ctx_t *ctx)
{
    if (ctx->manager_running) {
        ctx->manager_running = 0;
        pthread_join(ctx->manager_tid, NULL);
        DIAG_DEBUG("ncs %s manager stop.\n", ctx->name);
    }

    return 0;
}

ncs_ctx_t *ncs_create(char *name, int proto)
{
    ncs_ctx_t *ctx = malloc(sizeof(ncs_ctx_t));
    if (ctx == NULL) {
        return NULL;
    }

    memset(ctx, 0, sizeof(ncs_ctx_t));

    ctx->name = name;
    ctx->client_sock = -1;
    ctx->server_sock = -1;
    ctx->server_connid = -1;
    ctx->manager_paused = 1;
    ctx->clientinfo_changed = 0;
    ctx->serverinfo_changed = 0;
    ctx->recv_timeout = -1;
    ctx->send_timeout = -1;
    ctx->client_error = 0;
    ctx->server_error = 0;
    ctx->client_rcvbuf = 8192;
    ctx->server_rcvbuf = 8192;
    ctx->client_sndbuf = 8192;
    ctx->server_sndbuf = 8192;
    ctx->client_linger = 0;
    ctx->server_linger = 0;
    ctx->keep_alive = 0;
    ctx->is_valid = 1;
    ctx->is_udp = (proto == 0x11) ? 1 : 0;
    ctx->client_peerlen = sizeof(struct sockaddr);
    ctx->server_peerlen = sizeof(struct sockaddr);

    mutex_init(&ctx->mutex);

    if (ncs_manager_init(ctx)) {
        free(ctx);
        return NULL;
    }

    return ctx;
}

void ncs_destroy(ncs_ctx_t *ctx)
{
    if (ctx) {
        if (ctx->is_valid) {
            ctx->is_valid = 0;

            if (ctx->server_started) {
                ncs_server_stop(ctx);
            }

            if (ctx->client_started) {
                ctx->keep_alive = 0;
                ncs_client_stop(ctx);
            }

            ncs_manager_fini(ctx);
            mutex_destroy(&ctx->mutex);
            free(ctx);
        }
    }
}

void ncs_mutex_lock(ncs_ctx_t *ctx)
{
    mutex_lock(&ctx->mutex);
}

void ncs_mutex_unlock(ncs_ctx_t *ctx)
{
    mutex_unlock(&ctx->mutex);
}

int ncs_setup(ncs_ctx_t *ctx, char *local_addr, uint16_t local_port, char *remote_addr, uint16_t remote_port)
{
    if (ctx == NULL) {
        return -EINVAL;
    }

    if (local_addr != NULL) {
        if (strcmp(local_addr, ctx->local_addr)) {
            strncpy(ctx->local_addr, local_addr, sizeof(ctx->local_addr));
            ctx->serverinfo_changed = 1;
        }
    }

    if (local_port != 0) {
        if (local_port != ctx->local_port) {
            ctx->local_port = local_port;
            ctx->serverinfo_changed = 1;
        }
    }

    if (remote_addr != NULL) {
        if (strcmp(remote_addr, ctx->remote_addr)) {
            strncpy(ctx->remote_addr, remote_addr, sizeof(ctx->remote_addr));
            ctx->clientinfo_changed = 1;
        }
    }

    if (remote_port != 0) {
        if (remote_port != ctx->remote_port) {
            ctx->remote_port = remote_port;
            ctx->clientinfo_changed = 1;
        }
    }

    return 0;
}

int ncs_timeout(ncs_ctx_t *ctx, int recv_timeout, int send_timeout)
{
    if (ctx == NULL) {
        return -EINVAL;
    }

    ctx->recv_timeout = recv_timeout;
    ctx->send_timeout = send_timeout;

    return 0;
}

int ncs_setbuf(ncs_ctx_t *ctx, int rcvbuf, int sndbuf)
{
    if (ctx == NULL) {
        return -EINVAL;
    }

    ctx->client_rcvbuf = rcvbuf;
    ctx->server_rcvbuf = rcvbuf;
    ctx->client_sndbuf = sndbuf;
    ctx->server_sndbuf = sndbuf;
    return 0;
}

int ncs_setlinger(ncs_ctx_t *ctx, int linger)
{
    if (ctx == NULL) {
        return -EINVAL;
    }

    ctx->client_linger = linger;
    ctx->server_linger = linger;
    return 0;
}

int ncs_setkeepalive(ncs_ctx_t *ctx, int keepalive)
{
    if (ctx == NULL) {
        return -EINVAL;
    }

    ctx->keep_alive = keepalive;
    return 0;
}

int ncs_client_enable(ncs_ctx_t *ctx)
{
    if (!ctx->client_enable) {
        ctx->client_enable = 1;
        ctx->clientinfo_changed = 1;
    }

    return 0;
}

int ncs_client_disable(ncs_ctx_t *ctx)
{
    if (ctx->client_enable) {
        ctx->client_enable = 0;
        ctx->clientinfo_changed = 1;
    }

    return 0;
}

int ncs_server_enable(ncs_ctx_t *ctx)
{
    if (!ctx->server_enable) {
        ctx->server_enable = 1;
        ctx->serverinfo_changed = 1;
    }

    return 0;
}

int ncs_server_disable(ncs_ctx_t *ctx)
{
    if (ctx->server_enable) {
        ctx->server_enable = 0;
        ctx->serverinfo_changed = 1;
    }

    return 0;
}

int ncs_client_send(ncs_ctx_t *ctx, char *data, int length)
{
    int sent = 0;

    if (ctx->is_udp) {
        ctx->client_error = ncs_buffer_sendto(ctx->client_sock, data, length, &sent, &ctx->client_peeraddr, ctx->client_peerlen, ctx->send_timeout);
    } else {
        ctx->client_error = ncs_buffer_send(ctx->client_sock, data, length, &sent, ctx->send_timeout);
    }

    return sent;
}

int ncs_client_recv(ncs_ctx_t *ctx, char *data, int length)
{
    int got = 0;

    if (ctx->is_udp) {
        ctx->client_error = ncs_buffer_recvfrom(ctx->client_sock, data, length, &got, &ctx->client_peeraddr, &ctx->client_peerlen, ctx->recv_timeout);
    } else {
        ctx->client_error = ncs_buffer_recv(ctx->client_sock, data, length, &got, ctx->recv_timeout);
    }

    return got;
}

int ncs_server_send(ncs_ctx_t *ctx, char *data, int length)
{
    int sent = 0;

    if (ctx->is_udp) {
        ctx->server_error = ncs_buffer_sendto(ctx->server_connid, data, length, &sent, &ctx->server_peeraddr, ctx->server_peerlen, ctx->send_timeout);
    } else {
        ctx->server_error = ncs_buffer_send(ctx->server_connid, data, length, &sent, ctx->send_timeout);
    }

    return sent;
}

int ncs_server_recv(ncs_ctx_t *ctx, char *data, int length)
{
    int got = 0;

    if (ctx->is_udp) {
        ctx->server_error = ncs_buffer_recvfrom(ctx->server_connid, data, length, &got, &ctx->server_peeraddr, &ctx->server_peerlen, ctx->recv_timeout);
    } else {
        ctx->server_error = ncs_buffer_recv(ctx->server_connid, data, length, &got, ctx->recv_timeout);
    }

    return got;
}

int ncs_server_register(ncs_ctx_t *ctx, int (*server_handler)(struct ncs_ctx_st *ctx))
{
    ctx->server_handler = server_handler;

    return 0;
}
