#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netpacket/packet.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <net/if.h>

#include "libnio.h"
#include "libdiag.h"
#include "libsysmgr.h"

typedef struct raw_sock_priv_st {
    int sock;
    int mtu;
    int promisc;
    uint16_t proto;
    uint16_t timeout;
    uint16_t padding_begin;
    uint16_t padding_end;
    int rcvbuf_size;
    int sndbuf_size;
    struct sockaddr_ll address;
} raw_sock_priv_t;

/*
 * args: {proto, timeout, rcvbuf, sndbuf, mtu, promisc, padding_begin, padding_end}
 */
int raw_sock_open(nio_ctx_t *ctx, int argc, int *argv)
{
    int ret;
    raw_sock_priv_t *priv;

    if (argc != 8)
        return -EINVAL;

    priv = malloc(sizeof(raw_sock_priv_t));
    if (priv == NULL) {
        return -ENOMEM;
    }

    priv->proto = argv[0];
    priv->timeout = argv[1];
    priv->rcvbuf_size = argv[2];
    priv->sndbuf_size = argv[3];
    priv->mtu = argv[4];
    priv->promisc = argv[5];
    priv->padding_begin = argv[6];
    priv->padding_end = argv[7];

    ret = sys_netif_enable(ctx->ifname);
    if (ret < 0) {
        DIAG_ERROR("enable netif %s failed: %m\n", ctx->ifname);
        free(priv);
        return ret;
    }

   //if (priv->mtu) {
   //    ret = sys_netif_mtu_set(ctx->ifname, priv->mtu);
   //    if (ret < 0) {
   //        DIAG_ERROR("set netif %s mtu %d failed: %m\n", ctx->ifname, priv->mtu);
   //        free(priv);
   //        return ret;
   //    }
   //} else {
   //    priv->mtu = 1500;
   //}

    if (priv->promisc) {
        ret = sys_netif_promisc_enable(ctx->ifname);
        if (ret < 0) {
            DIAG_ERROR("enable netif %s promisc failed: %m\n", ctx->ifname);
            free(priv);
            return ret;
        }
    }

    priv->sock = socket(AF_PACKET, SOCK_RAW, htons(priv->proto));
    if (priv->sock < 0) {
        free(priv);
        return -ENOTSOCK;
    }

    memset(&priv->address, 0, sizeof(struct sockaddr_ll));
    priv->address.sll_family = AF_PACKET;
    priv->address.sll_ifindex = if_nametoindex(ctx->ifname);
    priv->address.sll_protocol = htons(priv->proto);
    if (bind(priv->sock, (struct sockaddr *)&priv->address, sizeof(priv->address)) < 0) {
        close(priv->sock);
        free(priv);
        return -EADDRINUSE;
    }

    setsockopt(priv->sock, SOL_SOCKET, SO_RCVBUF, (const char *) &priv->rcvbuf_size, sizeof(int));
    setsockopt(priv->sock, SOL_SOCKET, SO_SNDBUF, (const char *) &priv->sndbuf_size, sizeof(int));

    ctx->priv = priv;
    return 0;
}

void raw_sock_close(nio_ctx_t *ctx)
{
    raw_sock_priv_t *priv = ctx->priv;

    if (priv) {
        close(priv->sock);
        free(priv);
    }

    ctx->priv = NULL;
}

int raw_sock_read(raw_sock_priv_t *priv, uint8_t **pdata)
{
    int rxlen;
    int total = 0;
    int offset = 0;
    int blocksize = priv->mtu;
    uint8_t *data = NULL;
    uint8_t *newdata = NULL;

    total = blocksize;
    data = malloc(total);
    if (data == NULL)
        return -ENOMEM;

    while (1) {
        rxlen = recvfrom(priv->sock, data + offset, blocksize, MSG_DONTWAIT, NULL, NULL);
        if (rxlen < 0) {
            free(data);
            return -EIO;
        }

        if (rxlen < blocksize || rxlen == 0) {
            offset += rxlen;
            break;
        }

        total += blocksize;
        offset += rxlen;

        newdata = realloc(data, total);
        if (newdata == NULL) {
            free(data);
            return -ENOMEM;
        }

        data = newdata;
    }

    *pdata = data;
    return offset;
}

int raw_sock_recv(nio_ctx_t *ctx, nio_pkt_t *pkt)
{
    int ret = 0;
    fd_set fdset;
    uint8_t *data;
    struct timeval tv;
    raw_sock_priv_t *priv = ctx->priv;

    FD_ZERO(&fdset);
    FD_SET(priv->sock, &fdset);

    tv.tv_sec = priv->timeout;
    tv.tv_usec = 0;

    ret = select(priv->sock + 1, &fdset, NULL, NULL, &tv);
    if (ret <= 0)
        return -ETIMEDOUT;

    ret = raw_sock_read(priv, &data);
    if (ret < 0) {
        return ret;
    }

    pkt->length = ret;
    pkt->data = data;
    pkt->proto = ntohs(*(unsigned short *)(data+12));
    return 0;
}

int raw_sock_send(nio_ctx_t *ctx, uint16_t proto, uint8_t *data, int len)
{
    int ret;
    int offset = 0;
    raw_sock_priv_t *priv = ctx->priv;
    int length = ETH_HLEN + priv->padding_begin + len + priv->padding_end;

    uint8_t *buffer = malloc(length);
    if (buffer == NULL)
        return -ENOMEM;

    memcpy(buffer, ctx->dmac, 6); offset += 6;
    memcpy(buffer + offset, ctx->smac, 6); offset += 6;
    *(buffer + offset) = ((proto >> 8) & 0xFF); offset += 1;
    *(buffer + offset) = (proto & 0xFF); offset += 1;
    if (priv->padding_begin) {
        memset(buffer + offset, 0, priv->padding_begin);
        offset += priv->padding_begin;
    }
    memcpy(buffer + offset, data, len); offset += len;
    if (priv->padding_end) {
        memset(buffer + offset, 0, priv->padding_end);
    }

    ret = sendto(priv->sock, buffer, length, MSG_DONTWAIT, (struct sockaddr *) (&priv->address), sizeof(struct sockaddr_ll));
    if (ret != length) {
        DIAG_ERROR("send data length %d should be %d, errno %d\n", ret, length, errno);
        free(buffer);
        return -EIO;
    }

    free(buffer);
    return 0;
}

int raw_sock_forward(nio_ctx_t *ctx, uint16_t proto, nio_pkt_t *pkt)
{
    int ret;
    raw_sock_priv_t *priv = ctx->priv;

    ret = sendto(priv->sock, pkt->data, pkt->length, MSG_DONTWAIT, (struct sockaddr *) (&priv->address), sizeof(struct sockaddr_ll));
    if (ret != pkt->length) {
        DIAG_ERROR("send data length %d should be %d\n", ret, pkt->length);
        return -EIO;
    }

    free(pkt->data);
    return 0;
}

int raw_sock_drop(nio_ctx_t *ctx, nio_pkt_t *pkt)
{
    free(pkt->data);
    return 0;
}

struct nio_ops_st g_raw_sock_ops = {
    .open = raw_sock_open,
    .close = raw_sock_close,
    .recv = raw_sock_recv,
    .send = raw_sock_send,
    .forward = raw_sock_forward,
    .drop = raw_sock_drop,
};

