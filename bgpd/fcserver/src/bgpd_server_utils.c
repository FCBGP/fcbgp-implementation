/********************************************************************************
 * File Name:    bgpd_server_utils.c
 * Author:       basilguo@163.com
 * Created Time: 2023-09-28 07:37:37
 * Description:
 ********************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <sqlite3.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <signal.h>
#include <pthread.h>

#include "ds_binding_message.h"
#include "dbutils.h"
#include "utils.h"
#include "libncs.h"
#include "libdiag.h"
#include "libhtable.h"

ncs_ctx_t *bgpd_ctx = NULL;

static int bm_sent_to_peer(const char *addr, const fcmsg_bm_t *bm,
        char *buffer, int bufferlen)
{
    int ret = 0;
    int sockfd = 0;
    int len = 0;
    struct sockaddr_in sockaddr;

    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        perror("socket()");
        return -1;
    }
    sockaddr.sin_family = AF_INET;
    sockaddr.sin_port = htons(FC_BROADCAST_PORT);
    inet_pton(AF_INET, addr, &sockaddr.sin_addr);
    if ((ret = connect(sockfd, (struct sockadd*)&sockaddr,
                    sizeof(sockaddr))) < 0)
    {
        perror("connect()");
        return -1;
    }

    while (len != bufferlen)
    {
        len = len + send(sockfd, buffer+len, bufferlen-len, 0);
    }

    close(sockfd);

    return 0;
}

static int bm_broadcast_to_peer(const fcmsg_bm_t *bm, char *buffer,
        int bufferlen)
{
    int i = 0;

    for (i=0; i<bm->fc_num; ++i)
    {
        // TODO wether asn is in aspath
        ht_node_as_t *node = htbl_meta_find(&g_fcserver.ht,
                &bm->fclist[i].current_asn);
        bm_sent_to_peer(node->ap.acs.ipv4, bm, buffer, bufferlen);
    }

    return 0;
}

int bm_write_to_db(const fcmsg_bm_t *bm)
{
    char sql[BUFSIZ] = {0};
    // base64 encode
    char buff_src_ip[BUFSIZ/4] = {0};
    char buff_dst_ip[BUFSIZ/4] = {0};
    char buff_fclist[BUFSIZ/4] = {0};
    unsigned char buff[BUFSIZ];
    int cur = 0, i = 0;
    socklen_t socklen;

    if (bm->ipversion == 4)
    {
        socklen = sizeof(struct sockaddr_in);
    } else if (bm->ipversion == 6)
    {
        DIAG_ERROR("THIS IS NOT supported: %d!\n", bm->ipversion);
        return 0;
    } else
    {
        DIAG_ERROR("THIS IS NOT supported: %d!\n", bm->ipversion);
        return -1;
    }

    // base64 encode src_ip
    cur = 0;
    memset(buff, 0, BUFSIZ);
    for (i=0; i<bm->src_ip_num; ++i)
    {
        inet_ntop(AF_INET, &bm->src_ip[i].ip, (char*)buff+cur, socklen);
        cur += socklen;
        snprintf(buff+cur, BUFSIZ, "%d", bm->src_ip[i].prefix_length);
        cur += sizeof(bm->src_ip[i].prefix_length);
    }
    base64_encode(buff, cur, buff_src_ip);

    // base64 encode dst_ip
    cur = 0;
    memset(buff, 0, BUFSIZ);
    for (i=0; i<bm->dst_ip_num; ++i)
    {
        inet_ntop(AF_INET, &bm->dst_ip[i].ip, (char*)buff+cur, socklen);
        cur += socklen;
        snprintf(buff+cur, BUFSIZ, "%d", bm->dst_ip[i].prefix_length);
        cur += sizeof(bm->dst_ip[i].prefix_length);
    }
    base64_encode(buff, cur, buff_dst_ip);

    // base64 encode fclist
    cur = 0;
    memset(buff, 0, BUFSIZ);
    for (i=0; i<bm->fc_num; ++i)
    {
        snprintf(buff+cur, BUFSIZ, "%s", (unsigned char *)&bm->fclist[i]);
        cur += sizeof(FC_t);
    }
    base64_encode(buff, cur, buff_fclist);

    snprintf(sql, BUFSIZ,
            "INSERT INTO fcs VALUES(%u, %u, %u, %u, %u, %u, %u, %u, %u,"
            "%u, %s, %s, %s, %s, %s)",
            bm->ipversion, bm->type, bm->action, bm->fc_num,
            bm->src_ip_num, bm->dst_ip_num, bm->siglen, bm->local_asn,
            bm->version, bm->subversion, buff_src_ip, buff_dst_ip,
            buff_fclist, bm->ski, bm->signature);
    db_exec(g_fcserver.db, sql, db_store_bm_handler, NULL);

    return 0;
}

static int pubkey_handler(const char *buff, int len)
{
    return 0;
}

int bm_verify_fc(FC_t *fclist, int size)
{
    return 0;
}

int bm_verify_signature(u8 *signature, u16 siglen)
{
    return 0;
}

// buff is starting from bm's ipversion
// is_bc: is broadcast msg
int bm_handler(char *buffer, int bufferlen, int is_bc)
{
    // remove header
    char *buff = buffer + 4;

    u32 i = 0;
    fcmsg_bm_t bm = {0};
    int cur = 0;
    int ret = 0;
    int ip_len = 0;

    if (buff[0] == 4) // ipv4
    {
        ip_len = 4;
    } else if (buff[0] == 6) // ipv6
    {
        ip_len = 16;
        DIAG_ERROR("Not supported now: %d\n", buff[0]);
        return 0;
    } else
    {
        DIAG_ERROR("Not supported now: %d\n", buff[0]);
    }

    memcpy(&bm.ipversion, buff, sizeof(u8));
    cur += sizeof(u8); // ipversion
    cur += sizeof(u8); // type
    cur += sizeof(u8); // action
    cur += sizeof(u8); // fc_num
    cur += sizeof(u8); // src_ip_num
    cur += sizeof(u8); // dst_ip_num
    cur += sizeof(u16); // siglen
    cur += sizeof(u32); // local_asn
    cur += sizeof(u32); // version
    cur += sizeof(u32); // subversion
    memcpy(&bm, buff, cur);

    // src_ip
    for (i=0; i<bm.src_ip_num; ++i)
    {
        memcpy(&bm.src_ip[i].ip, buff+cur, ip_len);
        memcpy(&bm.src_ip[i].prefix_length, buff+cur+4, 1);
        cur += ip_len + 1;
    }
    // dst_ip
    for (i=0; i<bm.dst_ip_num; ++i)
    {
        memcpy(&bm.dst_ip[i].ip, buff+cur, ip_len);
        memcpy(&bm.dst_ip[i].prefix_length, buff+cur+4, 1);
        cur += ip_len + 1;
    }
    // fclist
    int fc_fixlen = sizeof(u32) // prev asn
        +sizeof(u32) // curr asn
        +sizeof(u32) // next asn
        +sizeof(u8)*20 // ski
        +sizeof(u8)  // algo_id
        +sizeof(u8)  // flags
        +sizeof(u16); // siglen
    for (i=0; i<bm.fc_num; ++i)
    {
        memcpy(&bm.fclist[i], buff+cur, fc_fixlen);
        cur += fc_fixlen;
        memcpy(bm.fclist[i].sig, buff+cur, bm.fclist[i].siglen);
        cur += bm.fclist[i].siglen;
    }
    ret = bm_verify_fc(bm.fclist, bm.fc_num);
    ASSERT_RET(ret);

    // ski -- for signature
    memset(bm.ski, 0, 20);

    // signature
    if (!is_bc)
    {
        u64 sig = 0x0123456789abcdef;
        int last_len = bm.siglen;
        bm.siglen = 72;
        while (last_len > 0)
        {
            last_len -= 8;
            memcpy(bm.signature+last_len, &sig, 8);
        }
    } else
    {
        bm_verify_signature(bm.signature, bm.siglen);
    }

    bm_write_to_db(&bm);
    if (!is_bc)
    {
        // gen_acl(&bm);
        bm_broadcast_to_peer(&bm, buffer, bufferlen);
    }

    return 0;
}

int bgpd_server_handler(ncs_ctx_t *ctx)
{
    int len = 0;
    char buff[BUFSIZ];

    do
    {
        memset(buff, 0, BUFSIZ);
        len = ncs_server_recv(ctx, buff, BUFSIZ);
        DIAG_DEBUG("received from %s:%d %s:%d %s:%s, len = %d\n",
                ctx->remote_addr, ctx->remote_port,
                ctx->local_addr, ctx->local_port,
                ctx->server_peeraddr, ctx->client_peeraddr, len);
        if (len > 0)
        {
            if (buff[0] == 1) // pubkey
            {
                DIAG_ERROR("Not support pubkey\n");
                // TODO length
                pubkey_handler(buff+4, len-4);
                return 0;
            } else if (buff[0] == 2) // bm
            {
                // TODO length
                bm_handler(buff, len, 0);
            } else
            {
                DIAG_ERROR("Not support %d\n", buff[0]);
                return -1;
            }
        }
    } while (1);

    ncs_client_stop(ctx);

    return 0;
}

void *bgpd_server_create(void * args)
{
    (void) args;
    if ((bgpd_ctx = ncs_create("bgpd", TCP_PROTO)) == NULL)
    {
        DIAG_ERROR("create bgpd ncs failed\n");
        exit(-ENOMEM);
    }

    ncs_setup(bgpd_ctx, INADDR_ANY, FC_BGPD_PORT, NULL, 0);
    ncs_timeout(bgpd_ctx, 10, -1);
    ncs_setkeepalive(bgpd_ctx, 10);
    ncs_server_enable(bgpd_ctx);
    ncs_server_register(bgpd_ctx, bgpd_server_handler);
    ncs_manager_start(bgpd_ctx);

    return NULL;
}
