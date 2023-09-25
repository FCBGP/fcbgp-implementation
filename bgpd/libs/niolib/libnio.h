#ifndef LIBNIO_H
#define LIBNIO_H

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <pthread.h>

#include "liblist.h"

#define NIO_MPIPE 0
#define NIO_RAWSOCK 1

typedef struct nio_ctx_st nio_ctx_t;

typedef struct nio_pkt_st {
    uint16_t proto;
    uint16_t length;
    uint8_t *data;
    void *attr;
} nio_pkt_t;

struct nio_ops_st {
    int (*open)(nio_ctx_t *ctx, int argc, int *argv);
    void (*close)(nio_ctx_t *ctx);

    int (*recv)(nio_ctx_t *ctx, nio_pkt_t *pkt);
    int (*send)(nio_ctx_t *ctx, uint16_t proto, uint8_t *data, int len);
    int (*forward)(nio_ctx_t *ctx, uint16_t proto, nio_pkt_t *pkt);
    int (*forward6)(nio_ctx_t *ctx, uint16_t proto, nio_pkt_t *pkt);
    int (*drop)(nio_ctx_t *ctx, nio_pkt_t *pkt);
};

struct nio_ptype_st {
    uint16_t proto;
    struct list_head ptype_node;
    int (*handler)(nio_ctx_t *ctx, nio_pkt_t *pkt);
};

struct nio_ctx_st {
    char *ifname;
    uint8_t smac[6];
    uint8_t dmac[6];

    uint32_t rx_bytes;
    uint32_t rx_packets;
    uint32_t tx_bytes;
    uint32_t tx_packets;

    int verbose;
    int running;
    pthread_t pid;
    struct list_head ptype_head;

    void *priv;
    struct nio_ops_st *ops;
};

extern struct nio_ops_st g_raw_sock_ops;

extern nio_ctx_t *nio_create(char *ifname, uint8_t *smac, uint8_t *dmac, struct nio_ops_st *ops);
extern int nio_open(nio_ctx_t *ctx, int argc, int *argv);
extern void nio_close(nio_ctx_t *ctx);
extern int nio_start(nio_ctx_t *ctx);
extern void nio_stop(nio_ctx_t *ctx);
extern int nio_send(nio_ctx_t *ctx, uint16_t proto, uint8_t *data, int len);
extern int nio_forward(nio_ctx_t *ctx, uint16_t proto, nio_pkt_t *pkt);
extern int nio_forward6(nio_ctx_t *ctx, uint16_t proto, nio_pkt_t *pkt);
extern int nio_add_ptype(nio_ctx_t *ctx, uint16_t proto,
        int (*handler)(nio_ctx_t *ctx, nio_pkt_t *pkt));
extern int nio_drop(nio_ctx_t *ctx, nio_pkt_t *pkt);
extern int nio_verbose(nio_ctx_t *ctx, int verbose);

#endif
