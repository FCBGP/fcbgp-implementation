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
#include <netinet/in.h>
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

    static int
bm_sent_to_peer(const char *addr, const fcmsg_bm_t *bm,
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
    sockaddr.sin_port = htons(FC_PORT);
    inet_pton(AF_INET, addr, &sockaddr.sin_addr);
    if ((ret = connect(sockfd, (struct sockaddr*)&sockaddr,
                    sizeof(sockaddr))) < 0)
    {
        perror("connect()");
        return -1;
    }

    while (len != bufferlen)
    {
        len = len + send(sockfd, buffer+len, bufferlen-len, 0);
        printf("len = %d, bufferlen = %d\n", len, bufferlen);
    }

    close(sockfd);

    return 0;
}

    static int
bm_broadcast_to_peer(const fcmsg_bm_t *bm, char *buffer,
        int bufferlen)
{
    int i = 0;
    node_as_t meta;

    for (i=0; i<bm->fc_num; ++i)
    {
        // TODO wether asn is in aspath
        meta.asn = bm->fclist[i].current_asn;
        ht_node_as_t *node = htbl_meta_find(&g_fcserver.ht,
                &meta);
        if (node)
        {
            printf("sent to %d\n", node->asn);
            if (g_fcserver.local_asn != node->asn)
            {
                bm_sent_to_peer(node->ap.acs.ipv4,
                        bm, buffer, bufferlen);
            }
        }
    }

    return 0;
}

    int
bm_write_to_db(const fcmsg_bm_t *bm)
{
    char sql[BUFSIZ] = {0};
    // base64 encode
    char buff_src_ip[BUFF_SIZE] = {0};
    char buff_dst_ip[BUFF_SIZE] = {0};
    char buff_fclist[BUFF_SIZE] = {0};
    char buff_ski[100] = {0};
    char buff_signature[BUFF_SIZE] = {0};
    // char buff[BUFSIZ] = {0};
    int cur = 0, i = 0;
    socklen_t socklen;
    struct sockaddr_in *sin = NULL;
    struct sockaddr_in6 *sin6 = NULL;

    if (bm->ipversion == IPV4)
    {
        socklen = sizeof(struct sockaddr_in);
    } else if (bm->ipversion == IPV6)
    {
        socklen = sizeof(struct sockaddr_in6);
        DIAG_ERROR("THIS IS NOT supported: %d!\n", bm->ipversion);
        return 0;
    } else
    {
        DIAG_ERROR("THIS IS NOT supported: %d!\n", bm->ipversion);
        return -1;
    }

    // use , to split strings
    // base64 encode src_ip
    cur = 0;
    // memset(buff, 0, BUFSIZ);
    for (i=0; i<bm->src_ip_num; ++i)
    {
        if (bm->ipversion == IPV4)
        {
            sin = (struct sockaddr_in *)&(bm->src_ip[i].ip);
            inet_ntop(AF_INET, &sin->sin_addr, buff_src_ip+cur, socklen);
        } else {
            sin6 = (struct sockaddr_in6 *)&(bm->src_ip[i].ip);
            inet_ntop(AF_INET, &sin6->sin6_addr, buff_src_ip+cur, socklen);
        }
        cur += strlen(buff_src_ip+cur);
        snprintf(buff_src_ip+cur, BUFF_SIZE, "/%d,",
                bm->src_ip[i].prefix_length);
        cur += strlen(buff_src_ip+cur);
        DIAG_DEBUG("src: %s\n", buff_src_ip);
    }

    // base64_encode(buff, cur, buff_src_ip);

    // base64 encode dst_ip
    cur = 0;
    // memset(buff_dst_ip, 0, BUFSIZ);
    for (i=0; i<bm->dst_ip_num; ++i)
    {
        if (bm->ipversion == IPV4)
        {
            sin = (struct sockaddr_in *)&(bm->dst_ip[i].ip);
            inet_ntop(AF_INET, &sin->sin_addr, buff_dst_ip+cur, socklen);
        } else {
            sin6 = (struct sockaddr_in6 *)&(bm->dst_ip[i].ip);
            inet_ntop(AF_INET, &sin6->sin6_addr, buff_dst_ip+cur, socklen);
        }
        cur += strlen(buff_dst_ip+cur);
        snprintf(buff_dst_ip+cur, BUFF_SIZE, "/%d,", bm->dst_ip[i].prefix_length);
        cur += strlen(buff_dst_ip+cur);
        DIAG_DEBUG("dst: %s\n", buff_dst_ip);
    }
    // base64_encode(buff, cur, buff_dst_ip);

    // base64 encode fclist
    cur = 0;
    // memset(buff, 0, BUFSIZ);
    for (i=0; i<bm->fc_num; ++i)
    {
        snprintf(buff_fclist+cur, BUFF_SIZE, "%08X-%08X-%08X-",
                bm->fclist[i].previous_asn,
                bm->fclist[i].current_asn,
                bm->fclist[i].nexthop_asn);
        cur += 8*3 + 3;
        for (int j=0; j<20; ++j)
        {
            snprintf(buff_fclist+cur, BUFSIZ, "%02X",
                    bm->fclist[i].ski[j]);
            cur += 2;
        }
        snprintf(buff_fclist+cur, BUFF_SIZE, "-%02X-%02X-%04X-",
                bm->fclist[i].algo_id,
                bm->fclist[i].flags, bm->fclist[i].siglen);
        cur += 8 + 4;

        for (int j=0; j<bm->fclist[i].siglen; ++j)
        {
            snprintf(buff_fclist+cur, BUFF_SIZE, "%02X",
                bm->fclist[i].sig[j]);
            cur += 2;
        }
        snprintf(buff_fclist+cur, BUFF_SIZE, ",");
        cur += 1;
        DIAG_DEBUG("curlen: %d, fclist: %s\n", cur, buff_fclist);
    }
    // base64_encode(buff, cur, buff_fclist);

    /*
       DIAG_DEBUG("buff-srcip: %s\n", buff_src_ip);
       DIAG_DEBUG("buff-dstip: %s\n", buff_dst_ip);
       DIAG_DEBUG("buff-fclist: %s\n", buff_fclist);
       */

    // ski
    cur = 0;
    for (int j=0; j<20; ++j)
    {
        snprintf(buff_ski+cur, BUFF_SIZE, "%02X",
                bm->fclist[i].ski[j]);
        cur += 2;
    }
    // signature
    for (int j = 0; j < bm->siglen; ++j)
    {
        snprintf(buff_signature+j*2, BUFF_SIZE, "%02X",
                bm->signature[j]);
    }
    printf("signature: %s\n", buff_signature);
    snprintf(sql, BUFSIZ,
            "INSERT INTO fcs VALUES(%u, %u, %u, %u, %u, %u, %u, %u, %u, "
            "%u, '%s', '%s', '%s', '%s', '%s')",
            bm->ipversion, bm->type, bm->action, bm->fc_num,
            bm->src_ip_num, bm->dst_ip_num, bm->siglen, bm->local_asn,
            bm->version, bm->subversion, buff_src_ip, buff_dst_ip,
            buff_fclist, buff_ski, buff_signature);
    printf("SQL: %s\n", sql);
    db_exec(g_fcserver.db, sql, db_store_bm_handler, NULL);

    return 0;
}

    static int
pubkey_handler(const char *buff, int len)
{
    return 0;
}

    static int
bm_verify_fc(fcmsg_bm_t *bm)
{
    char msg[BUFSIZ];
    int ret = 0;
    int msglen = 0;
    int i = 0, j = 0;
    struct sockaddr_in *ip4;
    struct sockaddr_in6 *ip6;

    for (i=0; i<bm->fc_num; ++i)
    {
        memset(msg, 0, BUFSIZ);
        msglen = 0;
        // hash(prev_asn, curr_asn, next_asn, dst_ip)
        // asn
        memcpy(msg + msglen, &(bm->fclist[i].previous_asn), sizeof(u32));
        msglen += sizeof(u32);
        memcpy(msg + msglen, &(bm->fclist[i].current_asn), sizeof(u32));
        msglen += sizeof(u32);
        memcpy(msg + msglen, &(bm->fclist[i].nexthop_asn), sizeof(u32));
        msglen += sizeof(u32);
        // dst_ip
        for (j=0; j<bm->dst_ip_num; ++j)
        {
            if (bm->ipversion == IPV4)
            {
                ip4 = (struct sockaddr_in*)&(bm->dst_ip[j].ip);
                memcpy(msg+msglen, &(ip4->sin_addr), IP4_LENGTH);
                msglen += IP4_LENGTH;
            } else {
                ip6 = (struct sockaddr_in6*)&(bm->dst_ip[j].ip);
                memcpy(msg+msglen, &(ip6->sin6_addr), IP6_LENGTH);
                msglen += IP6_LENGTH;
            }
            memcpy(msg+msglen, &bm->dst_ip[j].prefix_length, 1);
            msglen += 1;
        }
        ret = ecdsa_verify(g_fcserver.pubkey, msg,
                bm->fclist[i].sig, bm->fclist[i].siglen);
        switch (ret)
        {
        case 1:
            printf("verify fc ok\n");
            break;
        case 0:
            printf("verify fc failed\n");
            break;
        default:
            printf("verify fc error\n");
            break;
        }
    }
    return 0;
}

// buff is starting from bm's ipversion
// msg_type: is broadcast msg
    int
bm_handler(char *buffer, int bufferlen, int msg_type)
{
    // remove header
    char buff_new_msg[BUFSIZ] = {0};
    memcpy(buff_new_msg, buffer, bufferlen);
    char *buff = buff_new_msg + HDR_GENERAL_LENGTH;

    u32 i = 0;
    fcmsg_bm_t bm = {0};
    int cur = 0;
    int cur_siglen_pos = 0;
    int ret = 0;
    int ip_len = 0;
    char msg[BUFSIZ] = {0};
    unsigned char *sigbuff = NULL;
    unsigned int sigbufflen = 0;

    if (buff[0] == IPV4) // ipv4
    {
        ip_len = IP4_LENGTH;
    } else if (buff[0] == IPV6) // ipv6
    {
        ip_len = IP6_LENGTH;
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
    cur_siglen_pos = cur;
    cur += sizeof(u16); // siglen
    cur += sizeof(u32); // local_asn
    cur += sizeof(u32); // version
    cur += sizeof(u32); // subversion
    memcpy(&bm, buff, cur);

    bm.siglen = ntohs(bm.siglen);
    bm.local_asn = ntohl(bm.local_asn);
    bm.version = ntohl(bm.version);
    bm.subversion = ntohl(bm.subversion);

    // src_ip
    for (i=0; i<bm.src_ip_num; ++i)
    {
        if (bm.ipversion == IPV4)
        {
            struct sockaddr_in* addr = &bm.src_ip[i].ip;
            memcpy(&(addr->sin_addr),
                    buff+cur, sizeof(struct in_addr));
        } else
        {
            struct sockaddr_in6* addr = &bm.src_ip[i].ip;
            memcpy(&(addr->sin6_addr),
                    buff+cur, sizeof(struct in6_addr));
        }
        memcpy(&bm.src_ip[i].prefix_length, buff+cur+ip_len, 1);
        cur += ip_len + 1;
    }

    // dst_ip
    for (i=0; i<bm.dst_ip_num; ++i)
    {
        if (bm.ipversion == IPV4)
        {
            struct sockaddr_in* addr = &bm.dst_ip[i].ip;
            memcpy(&(addr->sin_addr),
                    buff+cur, sizeof(struct in_addr));
        } else
        {
            struct sockaddr_in6* addr = &bm.dst_ip[i].ip;
            memcpy(&(addr->sin6_addr),
                    buff+cur, sizeof(struct in6_addr));
        }
        memcpy(&bm.dst_ip[i].prefix_length, buff+cur+ip_len, 1);
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
        bm.fclist[i].previous_asn = ntohl(bm.fclist[i].previous_asn);
        bm.fclist[i].current_asn = ntohl(bm.fclist[i].current_asn);
        bm.fclist[i].nexthop_asn = ntohl(bm.fclist[i].nexthop_asn);
        bm.fclist[i].siglen = ntohs(bm.fclist[i].siglen);
        memcpy(bm.fclist[i].sig, buff+cur, bm.fclist[i].siglen);
        cur += bm.fclist[i].siglen;
    }

    // TODO verify fc
    ret = bm_verify_fc(&bm);
    ASSERT_RET(ret);

    // TODO need read from g_fcserver.
    // ski -- for signature
    memset(bm.ski, 0, SKI_LENGTH);

    // signature to be signed and verified
    memcpy(msg, buff, cur);

    if (msg_type == MSG_BGPD)
    {
        // add signature for sending to peers
        ecdsa_sign(g_fcserver.prikey, msg, &sigbuff, &sigbufflen);
        memcpy(buff+cur+SKI_LENGTH, sigbuff, sigbufflen);
        bm.siglen = sigbufflen;

        sigbufflen = htons(sigbufflen);
        memcpy(&buff[cur_siglen_pos], &sigbufflen, sizeof(bm.siglen));
        memcpy(bm.signature, sigbuff, bm.siglen);
        OPENSSL_free(sigbuff);
    } else
    {
        // verify and remove signature
        memcpy(bm.signature, buff+cur+SKI_LENGTH, bm.siglen);
        ret = ecdsa_verify(g_fcserver.pubkey, msg, bm.signature, bm.siglen);
        switch (ret)
        {
            case 1:
                printf("verify sig ok\n");
                break;
            case 0:
                printf("verify sig failed\n");
                break;
            default:
                printf("verify sig error\n");
                break;
        }
    }

    // TODO
    // gen_acl(&bm);

    bm_write_to_db(&bm);

    if (msg_type == MSG_BGPD)
    {
        printf("broadcast to peers\n");
        buff_new_msg[0] = 3;  // bc msg
        bm_broadcast_to_peer(&bm, buff_new_msg,
                HDR_GENERAL_LENGTH+cur+SKI_LENGTH+bm.siglen);
    }

    return 0;
}

    int
bgpd_server_handler(ncs_ctx_t *ctx)
{
    int len = 0;
    char buff[BUFSIZ];

    do
    {
        memset(buff, 0, BUFSIZ);
        len = ncs_server_recv(ctx, buff, BUFSIZ);
        DIAG_DEBUG("len = %d, received from %s:%d %s:%d %s:%s\n",
                len, ctx->remote_addr, ctx->remote_port,
                ctx->local_addr, ctx->local_port,
                ctx->server_peeraddr, ctx->client_peeraddr);
        if (len > 0)
        {
            switch (buff[0])
            {
            case 1: // pubkey
                DIAG_ERROR("Not support pubkey\n");
                // TODO length
                pubkey_handler(buff, len);
                return 0;
            case 2: // bm
                // TODO length
                bm_handler(buff, len, MSG_BGPD);
                break;
            case 3: // broadcast msg
                // TODO length
                bm_handler(buff, len, MSG_BC);
                break;
            default:
                DIAG_ERROR("Not support %d\n", buff[0]);
                return -1;
            }
        }
    } while (0);

    ncs_client_stop(ctx);

    return 0;
}

    void *
bgpd_server_create(void * args)
{
    acs_t *acs = (acs_t *)args;

    if ((bgpd_ctx = ncs_create("bgpd", TCP_PROTO)) == NULL)
    {
        DIAG_ERROR("create bgpd ncs failed\n");
        exit(-ENOMEM);
    }

    ncs_setup(bgpd_ctx, acs->ipv4, FC_PORT, NULL, 0);
    ncs_timeout(bgpd_ctx, 10, -1);
    ncs_setkeepalive(bgpd_ctx, 10);
    ncs_server_enable(bgpd_ctx);
    ncs_server_register(bgpd_ctx, bgpd_server_handler);
    ncs_manager_start(bgpd_ctx);

    return NULL;
}
