#include "libmbs.h"
#include "libreq.h"
#include "libdiag.h"

req_ctx_t *req_create(char *name, char *address)
{
    req_ctx_t *ctx = malloc(sizeof(req_ctx_t));
    if (ctx == NULL) {
        return NULL;
    }

    memset(&ctx->sockaddr, 0, sizeof(struct sockaddr_un));

    ctx->sockaddr.sun_family = AF_UNIX;
    snprintf(ctx->sockaddr.sun_path, UNIX_PATH_MAX, address);

    ctx->fd = -1;
    ctx->name = name;
    ctx->address = address;

    ctx->input = stream_romopen(NULL, 0);
    if (ctx->input == NULL) {
        DIAG_ERROR("req open input stream failed.\n");
        free(ctx);
        return NULL;
    }

    mpack_init(&ctx->decoder, ctx->input, mpack_stream_reader, NULL);

    ctx->output = stream_ramopen(malloc, realloc, free);
    if (ctx->output == NULL) {
        DIAG_ERROR("req open output stream failed.\n");
        stream_close(ctx->input);
        free(ctx);
        return NULL;
    }

    mpack_init(&ctx->encoder, ctx->output, NULL, mpack_stream_writer);
    mutex_init(&ctx->mutex);

    return ctx;
}

req_ctx_t *req_duplicate(req_ctx_t *req)
{
    req_ctx_t *ctx = malloc(sizeof(req_ctx_t));
    if (ctx == NULL) {
        return NULL;
    }

    memset(&ctx->sockaddr, 0, sizeof(struct sockaddr_un));

    ctx->sockaddr.sun_family = AF_UNIX;
    snprintf(ctx->sockaddr.sun_path, UNIX_PATH_MAX, req->address);

    ctx->fd = -1;
    ctx->name = req->name;
    ctx->address = req->address;

    ctx->input = stream_romopen(NULL, 0);
    if (ctx->input == NULL) {
        DIAG_ERROR("req open input stream failed.\n");
        free(ctx);
        return NULL;
    }

    mpack_init(&ctx->decoder, ctx->input, mpack_stream_reader, NULL);

    ctx->output = stream_ramopen(malloc, realloc, free);
    if (ctx->output == NULL) {
        DIAG_ERROR("req open output stream failed.\n");
        stream_close(ctx->input);
        free(ctx);
        return NULL;
    }

    mpack_init(&ctx->encoder, ctx->output, NULL, mpack_stream_writer);
    mutex_init(&ctx->mutex);

    return ctx;
}

void req_destroy(req_ctx_t *ctx)
{
    if (ctx == NULL) {
        return;
    }

    // free the input msg at last.
    mbsfree(stream_address(ctx->input));
    stream_close(ctx->input);
    stream_close(ctx->output);

    if (ctx->fd > 0) {
        close(ctx->fd);
        ctx->fd = -1;
    }

    mutex_destroy(&ctx->mutex);
    free(ctx);
}

int req_open(req_ctx_t *ctx)
{
    int ret;
    int reuseaddr;
    struct timeval rcvtimeout;

    ctx->fd = socket(PF_UNIX, SOCK_STREAM, 0);
    if (ctx->fd < 0) {
        DIAG_ERROR("%s: socket create failed: %m\n", ctx->name);
        return -ENOTSOCK;
    }

    reuseaddr = 1;
    ret = setsockopt(ctx->fd, SOL_SOCKET, SO_REUSEADDR, &reuseaddr, sizeof(int));
    if (ret != 0) {
        DIAG_ERROR("%s: socket set SO_REUSEADDR failed: %m\n", ctx->name);
        return -ENOPROTOOPT;
    }

    rcvtimeout.tv_sec = 300;
    rcvtimeout.tv_usec = 0;
    ret = setsockopt(ctx->fd, SOL_SOCKET, SO_RCVTIMEO, &rcvtimeout, sizeof(struct timeval));
    if (ret != 0) {
        DIAG_ERROR("%s: socket set SO_RCVTIMEO failed: %m\n", ctx->name);
        return -ENOPROTOOPT;
    }

    return 0;
}

int req_close(req_ctx_t *ctx)
{
    if (ctx->fd > 0) {
        close(ctx->fd);
        ctx->fd = -1;
    }

    return 0;
}

int req_connect(req_ctx_t *ctx)
{
    int ret;

    ret = connect(ctx->fd, (struct sockaddr *)&ctx->sockaddr, sizeof(struct sockaddr_un));
    if (ret < 0) {
        DIAG_ERROR("%s: socket connect failed: %m\n", ctx->name);
        return -ECONNREFUSED;
    }

    return 0;
}

void req_switch(req_ctx_t *ctx, char *address)
{
    ctx->address = address;
    snprintf(ctx->sockaddr.sun_path, UNIX_PATH_MAX, address);
    return;
}

static mbs_t sock_recvmsg(int fd, mbs_t *pmsg)
{
    int rxlen;
    int blksize = 256;
    mbs_t msg = NULL;

    if (pmsg == NULL) {
        return NULL;
    }

    msg = *pmsg;
    if (msg == NULL) {
        msg = mbsnewsize(1500);
        if (msg == NULL) {
            return NULL;
        }
    }

    mbsclear(msg);
    while (1) {
        int eos = 0;
        int len = mbslen(msg);
        int size = mbssize(msg);

        if (len + blksize > size) {
            if (mbsexpand(&msg, blksize) == NULL) {
                mbsfree(msg);
                *pmsg = NULL;
                return NULL;
            }
        }

        rxlen = read(fd, msg + len, blksize);
        if (rxlen < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN) continue;

            mbsfree(msg);
            *pmsg = NULL;
            return NULL;
        }

        len += rxlen;

        if (len >= 4) {
            if (!memcmp(msg + len - 4, "\r\n\r\n", 4)) {
                eos = 1;
            }
        }

        if (rxlen == 0 || eos) {
            if (eos) {
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

int req_recvmsg(req_ctx_t *ctx)
{
    mbs_t nmsg = NULL;
    mbs_t msg = stream_address(ctx->input);

    nmsg = sock_recvmsg(ctx->fd, &msg);
    if (nmsg == NULL) {
        DIAG_ERROR("%s: socket recv failed: %m\n", ctx->name);
        stream_romset(ctx->input, NULL, 0);
        return -EIO;
    }

    stream_romset(ctx->input, nmsg, mbslen(nmsg));
    return mbslen(msg);
}

static int sock_sendmsg(int fd, char *msg, int msglen)
{
    int ret = 0;
    int offset = 0;
    int blksize = 1024;

loop:
    if (msglen - offset < blksize) {
        blksize = msglen - offset;
    }

    ret = write(fd, msg + offset, blksize);
    if (ret < 0) {
        if (errno == EINTR) goto loop;
        if (errno == EAGAIN) goto loop;
        return -EIO;
    }

    offset += ret;
    if (offset < msglen) {
        goto loop;
    }

    return offset;
}

int req_sendmsg(req_ctx_t *ctx)
{
    int ret;

    // append the mark to the end of message.
    stream_puts(ctx->output, "\r\n\r\n");

    ret = sock_sendmsg(ctx->fd, stream_address(ctx->output), stream_length(ctx->output));

    // We just flush the stream data and rewind the cursor to
    // the beginning of the memory after sendmsg, and the memory
    // will be kept in the output stream for next usage.
    stream_flush(ctx->output);
    return ret;
}

int req_checkresult(req_ctx_t *ctx)
{
    int ret;
    int result;
    uint32_t len;
    char buffer[32] = {0, };

    ret = mpack_read_map(&ctx->decoder, &len);
    if (!ret || len != 2) {
        DIAG_ERROR("%s: parse result map failed.\n", ctx->name);
        return -EBADMSG;
    }

    len = sizeof(buffer);
    ret = mpack_read_str(&ctx->decoder, buffer, &len);
    if (!ret || strcmp(buffer, "result")) {
        DIAG_ERROR("%s: parse result failed.\n", ctx->name);
        return -EBADMSG;
    }

    ret = mpack_read_int(&ctx->decoder, &result);
    if (!ret) {
        DIAG_ERROR("%s: parse result value failed.\n", ctx->name);
        return -EBADMSG;
    }

    len = sizeof(buffer);
    ret = mpack_read_str(&ctx->decoder, buffer, &len);
    if (!ret || strcmp(buffer, "data")) {
        DIAG_ERROR("%s: parse result data failed.\n", ctx->name);
        return -EBADMSG;
    }

    return (-result);
}

int req_request(req_ctx_t *ctx)
{
    int ret;

    mutex_lock(&ctx->mutex);
    ret = req_open(ctx);
    if (ret < 0) {
        mutex_unlock(&ctx->mutex);
        return ret;
    }

    ret = req_connect(ctx);
    if (ret < 0) {
        req_close(ctx);
        mutex_unlock(&ctx->mutex);
        return ret;
    }

    ret = req_sendmsg(ctx);
    if (ret < 0) {
        req_close(ctx);
        mutex_unlock(&ctx->mutex);
        return ret;
    }

    ret = req_recvmsg(ctx);
    if (ret < 0) {
        req_close(ctx);
        mutex_unlock(&ctx->mutex);
        return ret;
    }

    req_close(ctx);
    mutex_unlock(&ctx->mutex);
    return 0;
}

