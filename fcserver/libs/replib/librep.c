#include "librep.h"
#include "libdiag.h"
#include "libmbs.h"

static void rep_create_pidfile(rep_ctx_t* ctx)
{
    FILE* fp = NULL;
    int pid = getpid();

#ifdef PRJ_SUPPORT_DEBUG
    snprintf(ctx->pidfile, sizeof(ctx->pidfile), "/tmp/%s.pid", ctx->name);
#else
    snprintf(ctx->pidfile, sizeof(ctx->pidfile), "/var/run/%s.pid", ctx->name);
#endif

    fp = fopen(ctx->pidfile, "w");
    if (fp == NULL)
    {
        return;
    }

    fprintf(fp, "%d", pid);
    fclose(fp);
    return;
}

rep_ctx_t* rep_create(char* name, int workers, char* address)
{
    int i;
    int ret;

    rep_ctx_t* ctx = malloc(sizeof(rep_ctx_t));
    if (ctx == NULL)
    {
        return NULL;
    }

    ctx->dispatch = dispatch_create();
    if (ctx->dispatch == NULL)
    {
        free(ctx);
        return NULL;
    }

    ctx->fd = socket(PF_UNIX, SOCK_STREAM, 0);
    if (ctx->fd < 0)
    {
        DIAG_ERROR("socket create failed: %m\n");
        dispatch_destroy(ctx->dispatch);
        free(ctx);
        return NULL;
    }

    int reuseaddr = 1;
    ret = setsockopt(ctx->fd, SOL_SOCKET, SO_REUSEADDR, &reuseaddr,
                     sizeof(reuseaddr));
    if (ret < 0)
    {
        DIAG_ERROR("socket set option failed: %m\n");
        dispatch_destroy(ctx->dispatch);
        free(ctx);
        return NULL;
    }

    unlink(address);
    memset(&ctx->sockaddr, 0, sizeof(struct sockaddr_un));

    ctx->sockaddr.sun_family = AF_UNIX;
    snprintf(ctx->sockaddr.sun_path, UNIX_PATH_MAX, address);

    ret = bind(ctx->fd, (struct sockaddr*)&ctx->sockaddr,
               sizeof(struct sockaddr_un));
    if (ret != 0)
    {
        DIAG_ERROR("socket bind %s failed: %m\n", address);
        close(ctx->fd);
        dispatch_destroy(ctx->dispatch);
        free(ctx);
        return NULL;
    }

    ret = listen(ctx->fd, 100);
    if (ret != 0)
    {
        DIAG_ERROR("socket listen failed: %m\n");
        close(ctx->fd);
        dispatch_destroy(ctx->dispatch);
        free(ctx);
        return NULL;
    }

    ctx->listenerset = listenerset_create();
    if (ctx->listenerset == NULL)
    {
        DIAG_ERROR("create listenerset failed: %m\n");
        close(ctx->fd);
        dispatch_destroy(ctx->dispatch);
        free(ctx);
        return NULL;
    }

    ctx->name = name;
    ctx->workers = workers;
    ctx->address = address;
    ctx->workertbl = malloc(workers * sizeof(rep_worker_t));
    if (ctx->workertbl == NULL)
    {
        close(ctx->fd);
        dispatch_destroy(ctx->dispatch);
        free(ctx);
        return NULL;
    }

    for (i = 0; i < workers; i++)
    {
        rep_worker_t* worker = ctx->workertbl + i;

        worker->idx = i;
        worker->cid = -1;
        worker->tid = -1;
        worker->state = 0;
        worker->ctx = ctx;

        worker->input = stream_romopen(NULL, 0);
        if (worker->input == NULL)
        {
            close(ctx->fd);
            dispatch_destroy(ctx->dispatch);
            free(ctx);
            return NULL;
        }

        mpack_init(&worker->decoder, worker->input, mpack_stream_reader, NULL);

        worker->output = stream_ramopen(malloc, realloc, free);
        if (worker->input == NULL)
        {
            stream_close(worker->input);
            close(ctx->fd);
            dispatch_destroy(ctx->dispatch);
            free(ctx);
            return NULL;
        }

        mpack_init(&worker->encoder, worker->output, NULL, mpack_stream_writer);
    }

    mutex_init(&ctx->mutex);
    condition_init(&ctx->condition);

    rep_create_pidfile(ctx);
    return ctx;
}

void rep_destroy(rep_ctx_t* ctx)
{
    int i;

    if (ctx == NULL)
    {
        return;
    }

    if (ctx->fd != -1)
    {
        close(ctx->fd);
        ctx->fd = -1;
    }

    for (i = 0; i < ctx->workers; i++)
    {
        rep_worker_t* worker = ctx->workertbl + i;

        if (worker->state)
        {
            worker->state = 0;
            pthread_join(worker->tid, NULL);
            mbsfree(stream_address(worker->input));
            stream_close(worker->input);
            stream_close(worker->output);
        }
    }

    free(ctx->workertbl);
    ctx->workertbl = NULL;

    if (ctx->dispatch)
    {
        dispatch_destroy(ctx->dispatch);
        ctx->dispatch = NULL;
    }

    listenerset_destroy(ctx->listenerset);

    mutex_destroy(&ctx->mutex);
    condition_destroy(&ctx->condition);

    free(ctx);
}

static mbs_t sock_recvmsg(int fd, mbs_t* pmsg)
{
    int rxlen;
    int blksize = 256;
    mbs_t msg = NULL;

    if (pmsg == NULL)
    {
        return NULL;
    }

    msg = *pmsg;
    if (msg == NULL)
    {
        msg = mbsnewsize(1500);
        if (msg == NULL)
        {
            return NULL;
        }
    }

    mbsclear(msg);
    while (1)
    {
        int eos = 0;
        int len = mbslen(msg);
        int size = mbssize(msg);

        if (len + blksize > size)
        {
            if (mbsexpand(&msg, blksize) == NULL)
            {
                mbsfree(msg);
                *pmsg = NULL;
                return NULL;
            }
        }

        rxlen = read(fd, msg + len, blksize);
        if (rxlen < 0)
        {
            if (errno == EINTR)
                continue;
            if (errno == EAGAIN)
                continue;

            mbsfree(msg);
            *pmsg = NULL;
            return NULL;
        }

        len += rxlen;

        if (len >= 4)
        {
            if (!memcmp(msg + len - 4, "\r\n\r\n", 4))
            {
                eos = 1;
            }
        }

        if (rxlen == 0 || eos)
        {
            if (eos)
            {
                mbssetlen(msg, len - 4);
                msg[len - 4] = '\0';
            }

            break;
        }

        mbssetlen(msg, len);
        msg[len] = '\0';
    }

    *pmsg = msg;
    return msg;
}

int rep_recvmsg(rep_worker_t* worker)
{
    mbs_t nmsg = NULL;
    mbs_t msg = stream_address(worker->input);

    nmsg = sock_recvmsg(worker->cid, &msg);
    if (nmsg == NULL)
    {
        DIAG_ERROR("socket recv failed: %m\n");
        stream_romset(worker->input, NULL, 0);
        return -EIO;
    }

    stream_romset(worker->input, nmsg, mbslen(nmsg));
    return mbslen(nmsg);
}

static int sock_sendmsg(int fd, char* msg, int msglen)
{
    int ret = 0;
    int offset = 0;
    int blksize = 1024;

loop:
    if (msglen - offset < blksize)
    {
        blksize = msglen - offset;
    }

    ret = write(fd, msg + offset, blksize);
    if (ret < 0)
    {
        if (errno == EINTR)
            goto loop;
        if (errno == EAGAIN)
            goto loop;
        return ret;
    }

    offset += ret;
    if (offset < msglen)
    {
        goto loop;
    }

    return offset;
}

int rep_sendmsg(rep_worker_t* worker)
{
    int ret;

    // append the mark to the end of message.
    stream_puts(worker->output, "\r\n\r\n");

    ret = sock_sendmsg(worker->cid, stream_address(worker->output),
                       stream_length(worker->output));

    // We just flush the stream data and rewind the cursor to
    // the beginning of the memory after sendmsg, and the memory
    // will be kept in the output stream for next usage.
    stream_flush(worker->output);
    return ret;
}

int rep_packerr(rep_worker_t* worker, int error)
{
    // flush the data packed before this function.
    stream_flush(worker->output);

    mpack_write_map(&worker->encoder, 2);
    mpack_write_str(&worker->encoder, "result", 6);
    mpack_write_int(&worker->encoder, error);
    mpack_write_str(&worker->encoder, "data", 4);
    return 0;
}

int rep_senderr(rep_worker_t* worker, int error, char* fmt, ...)
{
    int len;
    va_list ap;
    char buf[800] = {
        0,
    };

    va_start(ap, fmt);
    len = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    rep_packerr(worker, error);
    mpack_write_str(&worker->encoder, buf, len);

    return rep_sendmsg(worker);
}

int rep_packok(rep_worker_t* worker)
{
    // flush the data packed before this function.
    stream_flush(worker->output);

    mpack_write_map(&worker->encoder, 2);
    mpack_write_str(&worker->encoder, "result", 6);
    mpack_write_int(&worker->encoder, 0);
    mpack_write_str(&worker->encoder, "data", 4);
    return 0;
}

int rep_sendok(rep_worker_t* worker, char* fmt, ...)
{
    int len;
    va_list ap;
    char buf[800] = {
        0,
    };

    va_start(ap, fmt);
    len = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    rep_packok(worker);
    mpack_write_str(&worker->encoder, buf, len);

    return rep_sendmsg(worker);
}

static void* rep_worker(void* arg)
{
    int ret;
    uint32_t commandsize;

    char command[MAX_COMMAND_SIZE] = {
        0,
    };
    rep_handler_t handler = NULL;

    rep_worker_t* worker = (rep_worker_t*)arg;
    rep_ctx_t* ctx = worker->ctx;

    worker->state = 1;
    DIAG_INFO("dispatch worker %d is starting...\n", worker->idx);

    while (1)
    {
        if (!worker->state)
        {
            DIAG_INFO("dispatch worker %d is stoping...\n", worker->idx);
            break;
        }

        if (worker->cid == -1)
        {
            usleep(1000);
            continue;
        }

        DIAG_VERBOSE("worker %d try to recv msg from sock %d...\n", worker->idx,
                     worker->cid);
        ret = rep_recvmsg(worker);
        if (ret <= 0)
        {
            close(worker->cid);
            worker->cid = -1;
            condition_signal(&ctx->condition);
            continue;
        }

        commandsize = MAX_COMMAND_SIZE;
        ret = mpack_read_str(&worker->decoder, command, &commandsize);
        if (!ret)
        {
            DIAG_ERROR("can't get the command from msg.\n");
            rep_senderr(worker, EBADMSG, "%s", strerror(EBADMSG));
            close(worker->cid);
            worker->cid = -1;
            condition_signal(&ctx->condition);
            continue;
        }

        handler = dispatch(ctx->dispatch, command, commandsize);
        if (handler == NULL)
        {
            DIAG_ERROR("command %s is not support.\n", command);
            rep_senderr(worker, ENOTSUP, "%s", strerror(ENOTSUP));
            close(worker->cid);
            worker->cid = -1;
            condition_signal(&ctx->condition);
            continue;
        }

        ret = handler(worker);
        if (ret < 0)
        {
            DIAG_ERROR("command %s process failed, ret %d.\n", command, ret);
            rep_senderr(worker, -ret, "operation failed: %s", strerror(-ret));
            close(worker->cid);
            worker->cid = -1;
            condition_signal(&ctx->condition);
            continue;
        }

        DIAG_VERBOSE("worker %d process command %s done\n", worker->idx,
                     command);
        close(worker->cid);
        worker->cid = -1;
        condition_signal(&ctx->condition);
    }

    pthread_exit((void*)0);
    return NULL;
}

static int rep_event_handler(listener_t* listener, listen_event_t type)
{
    struct sockaddr_in cliaddr;
    rep_ctx_t* ctx = listener->tag;
    socklen_t length = sizeof(struct sockaddr_in);

    if (type & LISTEN_EVENT_READ)
    {
        int i;
        struct timespec abstime;

        int cid = accept(ctx->fd, (struct sockaddr*)&cliaddr, &length);
        if (cid < 0)
        {
            DIAG_ERROR("socket accept failed: %m\n");
            return -ENOTCONN;
        }

        DIAG_DPRINT("recv event read connection %d.\n", cid);
        for (i = 0; i < ctx->workers; i++)
        {
            rep_worker_t* worker = ctx->workertbl + i;
            if (worker->cid < 0)
            {
                DIAG_VERBOSE("dispatch connection %d to worker %d\n", cid,
                             worker->idx);
                worker->cid = cid;
                cid = -1;
                break;
            }
        }

        if (cid != -1)
        {
            abstime.tv_sec = time(NULL) + 3;
            abstime.tv_nsec = 0;

            mutex_lock(&ctx->mutex);
            condition_timedwait(&ctx->condition, &ctx->mutex, &abstime);
            mutex_unlock(&ctx->mutex);

            for (i = 0; i < ctx->workers; i++)
            {
                rep_worker_t* worker = ctx->workertbl + i;
                if (worker->cid < 0)
                {
                    DIAG_VERBOSE("dispatch connection %d to worker %d\n", cid,
                                 worker->idx);
                    worker->cid = cid;
                    cid = -1;
                    break;
                }
            }

            if (cid != -1)
            {
                DIAG_ERROR("no worker services for this connection.\n");
                close(cid);
                cid = -1;
            }
        }
    }

    if (type & LISTEN_EVENT_TIMEOUT)
    {
        DIAG_DPRINT("recv event timeout.\n");
    }

    return 0;
}

int rep_start(rep_ctx_t* ctx)
{
    int i;

    if (dispatch_prepare(ctx->dispatch))
    {
        DIAG_ERROR("rep %s prepare dispatch failed.\n", ctx->name);
        return -EINVAL;
    }

    for (i = 0; i < ctx->workers; i++)
    {
        rep_worker_t* worker = ctx->workertbl + i;
        if (worker->state)
        {
            DIAG_ERROR("worker %d is running.\n", i);
            continue;
        }

        if (pthread_create(&worker->tid, NULL, rep_worker, (void*)worker) < 0)
        {
            DIAG_ERROR("pthread_create %d worker failed: %m\n", i);
            continue;
        }
    }

    listenerset_add(ctx->listenerset, ctx->fd, rep_event_handler,
                    LISTEN_EVENT_READ, ctx, 0);
    return 0;
}

int rep_add_timer(rep_ctx_t* ctx, int timeout, listener_handler_t handler)
{
    listenerset_addtimer(ctx->listenerset, handler, ctx, timeout);
    return 0;
}

int rep_loop(rep_ctx_t* ctx)
{
    listenerset_loop(ctx->listenerset);
    return 0;
}
