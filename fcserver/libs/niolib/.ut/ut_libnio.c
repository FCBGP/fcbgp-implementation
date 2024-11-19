#include "libnio.h"
#include "libdiag.h"
#include "libcrc32.h"
#include "libsysmgr.h"
#include "libmutex.h"
#include "libcondition.h"

#define NIO_DEMO_LENGTH 2500
#define NIO_DEMO_PROTO 0xD001

nio_ctx_t *g_demo_nio = NULL;

static uint8_t g_demo_smac[6] = {0, };
static uint8_t g_demo_dmac[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};

int demo_process_reply(nio_ctx_t *ctx, nio_pkt_t * pkt)
{
    uint32_t crc = 0;
    uint32_t index = 0;
    uint32_t crc_input = 0;
    int length = pkt->length - 14 - 2;
    char *reqbuf = (char *)pkt->data + 14 + 2;

    index = reqbuf[0];
    index |= (reqbuf[1] << 8);
    index |= (reqbuf[2] << 16);
    index |= (reqbuf[3] << 24);

    crc = crc32_run(0, reqbuf, length - 4);

    crc_input |= reqbuf[length - 4];
    crc_input |= (reqbuf[length - 3] << 8);
    crc_input |= (reqbuf[length - 2] << 16);
    crc_input |= (reqbuf[length - 1] << 24);

    if (crc != crc_input) {
        DIAG_ERROR("recv %d packet length %d crc %08x should be %08x\n", index, length, crc, crc_input);
    }

    nio_drop(ctx, pkt);

    return 0;
}

int demo_link_init(char *ifname)
{
    int ret;

    if (ifname == NULL) {
        DIAG_ERROR("invalid if name!\n");
        return -EINVAL;
    }

    if (g_demo_nio != NULL) {
        DIAG_ERROR("cfg nio exists!\n");
        return -EINVAL;
    }

    ret = sys_netif_ethaddr_get(ifname, g_demo_smac);
    if (ret < 0) {
        DIAG_ERROR("get demo interface %s ethaddr failed\n", ifname);
        return ret;
    }

    g_demo_nio = nio_create(ifname, g_demo_smac, g_demo_dmac, &g_raw_sock_ops);
    if (g_demo_nio == NULL) {
        DIAG_ERROR("create demo nio failed\n");
        return -ENOMEM;
    }

    int argc = 8;
    int proto = NIO_DEMO_PROTO;

    int argv[] = {proto, 2, 0x400000, 0x400000, 3000, 1, 2, 0};
    ret = nio_open(g_demo_nio, argc, argv);
    if (ret < 0) {
        DIAG_ERROR("open demo nio failed\n");
        nio_close(g_demo_nio);
        g_demo_nio = NULL;
        return ret;
    }

    ret = nio_add_ptype(g_demo_nio, proto, demo_process_reply);
    if (ret < 0) {
        DIAG_ERROR("add demo nio handler failed\n");
        nio_close(g_demo_nio);
        g_demo_nio = NULL;
        return ret;
    }

    ret = nio_start(g_demo_nio);
    if (ret < 0) {
        DIAG_ERROR("start demo nio failed\n");
        nio_close(g_demo_nio);
        g_demo_nio = NULL;
        return ret;
    }

    return 0;
}

int demo_link_fini(void)
{
    if (g_demo_nio) {
        nio_stop(g_demo_nio);
        nio_close(g_demo_nio);
        g_demo_nio = NULL;
    }
    return 0;
}

int main(int argc, char *argv[])
{
    int i, j;
    int ret = 0;
    int loops = 100000;
    int length = 0;
    int verbose = 0;
    uint32_t crc = 0;
    uint32_t index = 0;
    char *ifname = NULL;
    char reqbuf[NIO_DEMO_LENGTH + 8] = {0, };

    for (i=0; i<argc; i++) {
        if (strcmp(argv[i], "-i") == 0) {
            ifname = argv[i + 1];
        } else if (strcmp(argv[i], "-v") == 0) {
            verbose = 1;
        } else if (strcmp(argv[i], "-n") == 0) {
            loops = strtol(argv[i + 1], NULL, 0);
        } else if (strcmp(argv[i], "-l") == 0) {
            length = strtol(argv[i + 1], NULL, 0);
        } else if (strcmp(argv[i], "-h") == 0) {
            DIAG_INFO("%s -i <interface> -v | -h | -l <len> | -o <loop>\n", argv[0]);
            return 0;
        }
    }

    ret = demo_link_init(ifname);
    if (ret < 0) {
        DIAG_ERROR("demo link %s init failed\n", ifname);
        return ret;
    }

    if (verbose) {
        nio_verbose(g_demo_nio, 1);
    }

    if (length) {
        i = length;

        reqbuf[0] = (index & 0xFF);
        reqbuf[1] = (index & 0xFF00) >> 8;
        reqbuf[2] = (index & 0xFF0000) >> 16;
        reqbuf[3] = (index & 0xFF000000) >> 24;

        for (j=0; j<i; j++) {
            reqbuf[4 + j] = random() & 0xFF;
        }

        crc = crc32_run(0, reqbuf, i + 4);
        reqbuf[i+4] = crc & 0xFF;
        reqbuf[i+5] = (crc & 0xFF00) >> 8;
        reqbuf[i+6] = (crc & 0xFF0000) >> 16;
        reqbuf[i+7] = (crc & 0xFF000000) >> 24;

        ret = nio_send(g_demo_nio, NIO_DEMO_PROTO, (uint8_t *)reqbuf, i + 8);
        if (ret < 0) {
            DIAG_ERROR("send request packet failed.\n");
            return ret;
        }

        index++;
        DIAG_INFO("send %d/%d packets done.\n", NIO_DEMO_LENGTH, index);
        goto out;
    }

    while (loops--) {
        srandom(time(NULL));

        for (i=36; i<=NIO_DEMO_LENGTH; i++) {
            reqbuf[0] = (index & 0xFF);
            reqbuf[1] = (index & 0xFF00) >> 8;
            reqbuf[2] = (index & 0xFF0000) >> 16;
            reqbuf[3] = (index & 0xFF000000) >> 24;

            for (j=0; j<i; j++) {
                reqbuf[4 + j] = random() & 0xFF;
            }

            crc = crc32_run(0, reqbuf, i + 4);
            reqbuf[i+4] = crc & 0xFF;
            reqbuf[i+5] = (crc & 0xFF00) >> 8;
            reqbuf[i+6] = (crc & 0xFF0000) >> 16;
            reqbuf[i+7] = (crc & 0xFF000000) >> 24;

            ret = nio_send(g_demo_nio, NIO_DEMO_PROTO, (uint8_t *)reqbuf, i + 8);
            if (ret < 0) {
                DIAG_ERROR("send request packet failed.\n");
                return ret;
            }

            index++;
        }

        DIAG_INFO("send %d/%d packets done.\n", NIO_DEMO_LENGTH, index);
    }

out:
    nio_stop(g_demo_nio);
    nio_close(g_demo_nio);
    return 0;
}

