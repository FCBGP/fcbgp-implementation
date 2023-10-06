#include <time.h>
#include <stdio.h>
#include <string.h>

#include "librep.h"
#include "libdiag.h"
#include "libapi.h"
#include "senderd.h"
#include "sender_rep.h"
#include "libncs.h"
#include "libncs6.h"
#include "libmbs.h"
#include "cJSON.h"
#include <libgen.h>
#include <arpa/inet.h>
#include <stdlib.h>

//#include "sender_client.h"

#define FILE_DEFAULT "/usr/local/etc/senderd.json"

#define PORT 3004

rep_ctx_t *g_sender_rep = NULL;
ncs_ctx_t *g_tcp_sender_ctx = NULL;
ncs6_ctx_t *g_tcp_sender6_ctx = NULL;

int sender_rep_init(void)
{
    g_sender_rep = rep_create("senderd", 4, SENDERD_ADDRESS);
    if (g_sender_rep == NULL) {
        DIAG_ERROR("create sender rep failed.\n");
        return -ENOMEM;
    }

    return 0;
}

int sender_rep_register(dispatch_command_t *commands)
{
    return dispatch_register_commands(g_sender_rep->dispatch, commands);
}

int sender_rep_start(void)
{
    return rep_start(g_sender_rep);
}

void sender_rep_loop(void)
{
    rep_loop(g_sender_rep);
}

void sender_rep_fini(void)
{
    rep_destroy(g_sender_rep);
}

int sender_server_handler(ncs_ctx_t *ctx)
{
    int ret = 0;
    int rxlen = 0;
    int txlen = 0;
    char buffer[256] = {0, };
    struct sockaddr_in *inaddr = (struct sockaddr_in *)&ctx->server_peeraddr;

    while (1) {
        ret = ncs_server_recv(ctx, buffer, 256);
        if (ret > 0) {
            DIAG_DEBUG("demo server recv from %08x:%d %d/%d bytes.\n", inaddr->sin_addr.s_addr, inaddr->sin_port, ret, rxlen);
        }

        if (ctx->server_error == -ESHUTDOWN) {
            DIAG_DEBUG("demo server shutdown.\n");
            break;
        }
    }

    return 0;
}

int sender6_server_handler(struct ncs6_ctx_st *ctx)
{
//   int ret = 0;
//   int rxlen = 0;
//   int txlen = 0;
//   char buffer[256] = {0, };
//   struct sockaddr_in *inaddr = (struct sockaddr_in *)&ctx->server_peeraddr;
//
//   while (1) {
//       ret = ncs_server_recv(ctx, buffer, 256);
//       if (ret > 0) {
//           DIAG_DEBUG("demo server recv from %08x:%d %d/%d bytes.\n", inaddr->sin_addr.s_addr, inaddr->sin_port, ret, rxlen);
//       }
//
//       if (ctx->server_error == -ESHUTDOWN) {
//           DIAG_DEBUG("demo server shutdown.\n");
//           break;
//       }
//   }
//
    return 0;
}
int ipv4_server_init()
{
    int proto = 6;
    uint16_t local_port = 3004;
    char *local_addr = "0.0.0.0";

    g_tcp_sender_ctx = ncs_create("ipv4_sender", 6);
    if (g_tcp_sender_ctx == NULL) {
        DIAG_ERROR("create tcp sender ncs failed\n");
        return -ENOMEM;
    }

    ncs_setup(g_tcp_sender_ctx, local_addr, local_port, NULL, 0);
    ncs_timeout(g_tcp_sender_ctx, 10, -1);

    ncs_server_enable(g_tcp_sender_ctx);

    ncs_server_register(g_tcp_sender_ctx, sender_server_handler);

    ncs_manager_start(g_tcp_sender_ctx);

    return 0;
}

int ipv6_server_init()
{
    int proto = 6;
    uint16_t local_port = 3004;
    char *local_addr = "::";

    g_tcp_sender6_ctx = ncs6_create("ipv6_sender", 6);
    if (g_tcp_sender6_ctx == NULL) {
        DIAG_ERROR("create tcp sender ncs6 failed\n");
        return -ENOMEM;
    }

    ncs6_setup(g_tcp_sender6_ctx, local_addr, local_port, NULL, 0);
    ncs6_timeout(g_tcp_sender6_ctx, 10, -1);

    ncs6_server_enable(g_tcp_sender6_ctx);

    ncs6_server_register(g_tcp_sender6_ctx, sender_server_handler);

    ncs6_manager_start(g_tcp_sender6_ctx);

    return 0;
}

int ncs_sender_init()
{
    int ret = 0;

    ret = ipv4_server_init();
    if (ret < 0) {
        DIAG_ERROR("ipv4 server init failed.\n");
        return -1;
    }

    ret = ipv6_server_init();
    if (ret < 0) {
        DIAG_ERROR("ipv6 server init failed.\n");
        return -1;
    }

    return ret;
}

int sender_version_rep(rep_worker_t *worker)
{
    rep_packok(worker);

    mpack_write_fmt(&worker->encoder, "%s", "0.1");

    return rep_sendmsg(worker);
}

static cJSON * parse_config(char *fname)
{
    DIAG_INFO("parse_config\n");
    mbs_t mbs = NULL;
    mbs_t data = NULL;
    cJSON * start = NULL;

    FILE *fp = NULL;
    DIAG_INFO("open file %s.\n", fname);
    fp = fopen(fname, "r");
    if (fp == NULL) {
        DIAG_ERROR("open %s failed: %d.\n", fname, errno);
        return -ENOENT;
    }

    while (1) {
        mbs = mbsreadline(fp);
        if (mbs == NULL) {
            break;
        }

        mbscatmbs(&data, mbs);
        mbsfree(mbs);
    }

    fclose(fp);

    start = cJSON_Parse(data);

    return start;
}

static int gen_payload(char *data, unsigned int *len, cJSON *json_start)
{
    DIAG_INFO("gen payload\n");
    int ret = 0;
    SRV_PKT_FMT_t pkt_payload = {0};
    cJSON *payload = NULL;
    cJSON * tmp = NULL;

    memset(data, 0, *len);
    *len = 0;
    if (json_start == NULL) {
        DIAG_ERROR("read json file failed.\n");
        return -1;
    }

    payload = cJSON_GetObjectItem(json_start, "payload");
    if (payload == NULL) {
        DIAG_ERROR("no payload in json file.\n");
        return -1;
    }

    pkt_payload.ip_version = (tmp = cJSON_GetObjectItem(payload, "ip_version")) ? (uint8_t)tmp->valueint: 0;
    if (pkt_payload.ip_version != 4 && pkt_payload.ip_version != 6) {
        DIAG_ERROR("only support 4 or 6");
        return -1;
    }
    pkt_payload.prefix_length = (tmp = cJSON_GetObjectItem(payload, "prefix_length")) ? (uint8_t)tmp->valueint: 0;
    pkt_payload.src_prelen = (tmp = cJSON_GetObjectItem(payload, "src_prelen")) ? (uint8_t)tmp->valueint: 0;
    pkt_payload.dst_prelen = (tmp = cJSON_GetObjectItem(payload, "dst_prelen")) ? (uint8_t)tmp->valueint: 0;
    pkt_payload.rule_type = (tmp = cJSON_GetObjectItem(payload, "rule_type")) ? (uint8_t)tmp->valueint: 0;
    pkt_payload.port_type = (tmp = cJSON_GetObjectItem(payload, "port_type")) ? (uint8_t)tmp->valueint: 0;
    pkt_payload.protocol = (tmp = cJSON_GetObjectItem(payload, "protocol")) ? (uint8_t)tmp->valueint: 0;
    if (pkt_payload.ip_version == 4) {
        tmp = cJSON_GetObjectItem(payload, "ipv4_src");
        if (tmp) {
            ret = inet_pton(AF_INET, tmp->valuestring, &pkt_payload.src_ip.ip4);
            if (ret != 1) {
                DIAG_ERROR("ip4_src address %s is invalid.\n", tmp->valuestring);
                return -1;
            }
        }

        tmp = cJSON_GetObjectItem(payload, "ipv4_dst");
        if (tmp) {
            ret = inet_pton(AF_INET, tmp->valuestring, &pkt_payload.dst_ip.ip4);
            if (ret != 1) {
                DIAG_ERROR("ip4_dst address %s is invalid.\n", tmp->valuestring);
                return -1;
            }
        }
    } else if (pkt_payload.ip_version == 6) {
        tmp = cJSON_GetObjectItem(payload, "ipv6_src");
        if (tmp) {
            ret = inet_pton(AF_INET6, tmp->valuestring, &pkt_payload.src_ip.ip6);
            if (ret != 1) {
                DIAG_ERROR("ip6_src address %s is invalid.\n", tmp->valuestring);
                return -1;
            }
        }

        tmp = cJSON_GetObjectItem(payload, "ipv6_dst");
        if (tmp) {
            ret = inet_pton(AF_INET6, tmp->valuestring, &pkt_payload.dst_ip.ip6);
            if (ret != 1) {
                DIAG_ERROR("ip6_dst address %s is invalid.\n", tmp->valuestring);
                return -1;
            }
        }
    }
    pkt_payload.src_port = (tmp = cJSON_GetObjectItem(payload, "src_port")) ? tmp->valueint: 0;
    pkt_payload.dst_port = (tmp = cJSON_GetObjectItem(payload, "dst_port")) ? tmp->valueint: 0;
    pkt_payload.port = (tmp = cJSON_GetObjectItem(payload, "port")) ? tmp->valueint: 0;
    memcpy(data+*len, &pkt_payload.ip_version, sizeof(pkt_payload.ip_version)); *len+=sizeof(pkt_payload.ip_version);
    memcpy(data+*len, &pkt_payload.prefix_length, sizeof(pkt_payload.prefix_length)); *len+=sizeof(pkt_payload.prefix_length);
    memcpy(data+*len, &pkt_payload.src_prelen, sizeof(pkt_payload.src_prelen)); *len+=sizeof(pkt_payload.src_prelen);
    memcpy(data+*len, &pkt_payload.dst_prelen, sizeof(pkt_payload.dst_prelen)); *len+=sizeof(pkt_payload.dst_prelen);
    memcpy(data+*len, &pkt_payload.rule_type, sizeof(pkt_payload.rule_type)); *len+=sizeof(pkt_payload.rule_type);
    memcpy(data+*len, &pkt_payload.port_type, sizeof(pkt_payload.port_type)); *len+=sizeof(pkt_payload.port_type);
    memcpy(data+*len, &pkt_payload.protocol, sizeof(pkt_payload.protocol)); *len+=sizeof(pkt_payload.protocol);
    memcpy(data+*len, &pkt_payload.reserved, sizeof(pkt_payload.reserved)); *len+=sizeof(pkt_payload.reserved);
    if (pkt_payload.ip_version == 4) {
        memcpy(data+*len, &pkt_payload.src_ip.ip4, sizeof(pkt_payload.src_ip.ip4)); *len+=sizeof(pkt_payload.src_ip.ip4);
        memcpy(data+*len, &pkt_payload.dst_ip.ip4, sizeof(pkt_payload.dst_ip.ip4)); *len+=sizeof(pkt_payload.dst_ip.ip4);
    } else if (pkt_payload.ip_version == 6) {
        memcpy(data+*len, &pkt_payload.src_ip.ip6, sizeof(pkt_payload.src_ip.ip6)); *len+=sizeof(pkt_payload.src_ip.ip6);
        memcpy(data+*len, &pkt_payload.dst_ip.ip6, sizeof(pkt_payload.dst_ip.ip6)); *len+=sizeof(pkt_payload.dst_ip.ip6);
    }
    memcpy(data+*len, &pkt_payload.src_port, sizeof(pkt_payload.src_port)); *len+=sizeof(pkt_payload.src_port);
    memcpy(data+*len, &pkt_payload.dst_port, sizeof(pkt_payload.dst_port)); *len+=sizeof(pkt_payload.dst_port);
    memcpy(data+*len, &pkt_payload.port, sizeof(pkt_payload.port)); *len+=sizeof(pkt_payload.port);

    int i = 0;
    for(i=0; i<*len; i++) {
        DIAG_INFO("%02x \n", (unsigned char)(data[i]));
    }

    return ret;
}

static int get_ipver(int *ipver, char *pipver, cJSON *send_json_start)
{
    cJSON *tmp = NULL;
    if (strcmp(pipver, "") == 0) {
        tmp = cJSON_GetObjectItem(send_json_start, "ipver");
        if (tmp) {
            if (strcmp(tmp->valuestring, "ipv4") == 0) {
                *ipver = 4;
            } else if (strcmp(tmp->valuestring, "ipv6") == 0) {
                *ipver = 6;
            } else {
                DIAG_ERROR("we can not get the ipver.\n");
                return -1;
            }
        }
    } else if (strcmp(pipver, "ipv4") == 0) {
        *ipver = 4;
    } else if (strcmp(pipver, "ipv6") == 0) {
        *ipver = 6;
    } else {
        DIAG_ERROR("only support ipv4 or ipv6");
        return -1;
    }

    return *ipver;
}

static int get_proto(int *proto, char *pproto, cJSON *send_json_start)
{
    cJSON *tmp = NULL;
    if (strcmp(pproto, "") == 0) {
        tmp = cJSON_GetObjectItem(send_json_start, "proto");
        if (tmp) {
            if (strcmp(tmp->valuestring, "udp") == 0) {
                *proto = 17;
            } else if (strcmp(tmp->valuestring, "tcp") == 0) {
                *proto = 6;
            } else {
                DIAG_ERROR("we can not get the proto");
                return -1;
            }
        }
    } else if (strcmp(pproto, "udp") == 0) {
        *proto = 17;
    } else if (strcmp(pproto, "tcp") == 0) {
        *proto = 6;
    } else {
        DIAG_ERROR("only support tcp or udp.\n");
        return -1;
    }

    return *proto;
}

static int send_pkt(char *data, int data_len, cJSON *send_json_start, char *pipver, char *psrcip, char *pdstip, char *pproto, int count, int interval)
{
    int ret = 0;
    int i;
    int txtot = 0;
    int rxtot = 0;
    int ipver = 0;
    int proto = 0;

    ret = get_ipver(&ipver, pipver, send_json_start);
    if (ret < 0) {
        DIAG_ERROR("get ipver failed.\n");
        return -1;
    }

    ret = get_proto(&proto, pproto, send_json_start);
    if (ret < 0) {
        DIAG_ERROR("get ipver failed.\n");
        return -1;
    }

    if(ipver == 4) {
        ncs_ctx_t *ncs_ctx = ncs_create((char *)"sender", proto);
        if (ncs_ctx == NULL) {
            return -ENOMEM;
        }
        ncs_setup(ncs_ctx, psrcip, 0, pdstip, PORT);
        ncs_client_enable(ncs_ctx);
        ncs_timeout(ncs_ctx, 10, -1);

        ret = ncs_client_start(ncs_ctx);
        if (ret < 0) {
            ncs_destroy(ncs_ctx);
            return ret;
        }

        ret = ncs_client_connect(ncs_ctx);
        if (ret < 0) {
            ncs_destroy(ncs_ctx);
            ncs_client_stop(ncs_ctx);
            return ret;
        }

        ret = ncs_client_send(ncs_ctx, data, data_len);
        if (ret < 0) {
            // TODO
            DIAG_ERROR("ipv4 %d send failed.\n", proto);
            return -1;
        }

    } else if (ipver == 6) {


    }
#if 0
    char * local_addr = ctx->local_addr;
    uint16_t local_port = ctx->local_port;
    char *remote_addr = ctx->remote_addr;
    uint16_t remote_port = ctx->remote_port;
    int proto = ctx->proto;

    if (!(ctx->proto == PROTO_TCP || ctx->proto == PROTO_UDP)){
        return -EINVAL;
    }


    ncs_ctx_t *ncs_ctx = ncs_create((char *)"sender", 6);
    if (ctx == NULL) {
        return -ENOMEM;
    }

    ncs_setup(ncs_ctx, local_addr, local_port, remote_addr, remote_port);
    ncs_client_enable(ncs_ctx);
    ncs_timeout(ncs_ctx, 10, -1);

    DIAG_DEBUG("local_addr: %s, lcoal_port: %d, remote_addr: %s, remote_port: %d.\n", local_addr, local_port, remote_addr, remote_port);

    ret = ncs_client_start(ncs_ctx);
    if (ret < 0) {
        ncs_destroy(ncs_ctx);
        return ret;
    }

    ret = ncs_client_connect(ncs_ctx);
    if (ret < 0) {
        ncs_destroy(ncs_ctx);
        ncs_client_stop(ncs_ctx);
        return ret;
    }

    ret = ncs_client_send(ncs_ctx, (char *)ctx->msg, sizeof(struct msg_st));
    if (ret < 0) {
    // TODO
        return -1;
    }
#endif
    return ret;
}

int sender_send(char *file, char *ipver, char *srcip, char *dstip, char *proto, int count, int interval)
{
    int ret = 0;
    int i = 0;
    char data[1024] = {0};
    unsigned int data_len = sizeof(data);
    cJSON * send_json_start = NULL;
    send_json_start = parse_config(file);
    if (send_json_start == NULL) {
        DIAG_ERROR("parse config failed: %d,\n", ret);
        return -1;
    }

    memset(data, 0, sizeof(data));
    ret = gen_payload(data, &data_len, send_json_start);
    if (ret < 0) {
        DIAG_ERROR("gen_pkt failed: %d,\n", ret);
        return -1;
    }

    ret = send_pkt(data, data_len, send_json_start, ipver, srcip, dstip, proto, count, interval);
    if (ret < 0) {
        DIAG_ERROR("send_pkt failed: %d,\n", ret);
        return -1;
    }

    return ret;
}

int sender_send_rep(rep_worker_t * worker)
{
    int ret;

    char file[64] = {0};
    uint32_t filelen = sizeof(file);
    ret = mpack_read_str(&worker->decoder, file, &filelen);
    if (!ret) {
        DIAG_ERROR("unpack file failed: %s\n", mpack_strerror(&worker->decoder));
        return -EBADMSG;
    }
    DIAG_INFO("file is %s filelen is %d.\n", file, filelen);

    char ipver[8] = {0};
    uint32_t ipverlen = sizeof(ipver);
    ret = mpack_read_str(&worker->decoder, ipver, &ipverlen);
    if (!ret) {
        DIAG_ERROR("unpack ipver failed: %s\n", mpack_strerror(&worker->decoder));
        return -EBADMSG;
    }
    DIAG_INFO("ipver is %s ipverlen is %d.\n", ipver, ipverlen);

    char srcip[64] = {0};
    uint32_t srciplen = sizeof(srcip);
    ret = mpack_read_str(&worker->decoder, srcip, &srciplen);
    if (!ret) {
        DIAG_ERROR("unpack srcip failed: %s\n", mpack_strerror(&worker->decoder));
        return -EBADMSG;
    }
    DIAG_INFO("srcip is %s srciplen is %d.\n", srcip, srciplen);

    char dstip[64] = {0};
    uint32_t dstiplen = sizeof(dstip);
    ret = mpack_read_str(&worker->decoder, dstip, &dstiplen);
    if (!ret) {
        DIAG_ERROR("unpack dstip failed: %s\n", mpack_strerror(&worker->decoder));
        return -EBADMSG;
    }
    DIAG_INFO("dstip is %s dstiplen is %d.\n", dstip, dstiplen);

    char proto[8] = {0};
    uint32_t protolen = sizeof(proto);
    ret = mpack_read_str(&worker->decoder, proto, &protolen);
    if (!ret) {
        DIAG_ERROR("unpack proto failed: %s\n", mpack_strerror(&worker->decoder));
        return -EBADMSG;
    }
    DIAG_INFO("proto is %s protolen is %d.\n", proto, protolen);

    int count = 0;
    ret = mpack_read_int(&worker->decoder, &count);
    if (!ret) {
        DIAG_ERROR("mpack read count failed%s\n", mpack_strerror(&worker->decoder));
        return -EBADMSG;
    }
    DIAG_INFO("count is %d.\n", count);
    if (count == 0) {
        count = 1;
    }

    int interval = 0;
    ret = mpack_read_int(&worker->decoder, &interval);
    if (!ret) {
        DIAG_ERROR("mpack read interval failed%s\n", mpack_strerror(&worker->decoder));
        return -EBADMSG;
    }
    DIAG_INFO("interval is %d.\n", interval);

    char path[64] = {0};
    strncpy(path, file, strlen(file)+1);
    if (filelen == 0) {
        strncpy(file, FILE_DEFAULT, strlen(FILE_DEFAULT)+1);
    } else {
          char *dirc, *basec, *bname, *dname;
           dirc = strdup(path);
           basec = strdup(path);
           dname = dirname(dirc);
           bname = basename(basec);
        if (strcmp(dname, ".") == 0) {
            snprintf(file, sizeof(file), "/usr/local/etc/%s", bname);
        }
    }
    DIAG_INFO("use file %s.\n", file);

    ret = sender_send(file, ipver, srcip, dstip, proto, count, interval);
    if (ret < 0) {
        DIAG_ERROR("send packets failed: %d.\n", ret);
        return rep_senderr(worker, -1, "send packets failed.");
    }

    return rep_sendok(worker, "done");
}

dispatch_command_t g_sender_commands[] = {
    {SENDER_COMMAND_VERSION, sender_version_rep},
    {SENDER_COMMAND_SEND, sender_send_rep},

    {NULL, NULL},
};

