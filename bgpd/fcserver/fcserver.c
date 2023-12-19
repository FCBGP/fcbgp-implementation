/********************************************************************************
 * File Name:    fcserver.c
 * Author:       basilguo@163.com
 * Created Time: 2023-09-25 10:09:53
 * Description:  FC SERVER UTILS
 ********************************************************************************/

#include <ctype.h>
#include "libdiag.h"
#include "fcconfig.h"
#include "dbutils.h"
#include "hashutils.h"
#include "sigutils.h"
#include "nftutils.h"
#include "fcserver.h"

FC_server_t g_fc_server = {0};

    void
fc_server_destroy(int signum)
{
    if (signum == SIGINT)
    {
        printf("recevied SIGINT\n");
        diag_fini();
        if (g_fc_server.fc_bgpd_ctx)
        {
            ncs_manager_stop(g_fc_server.fc_bgpd_ctx);
            ncs_destroy(g_fc_server.fc_bgpd_ctx);
            g_fc_server.fc_bgpd_ctx = NULL;
        }
        fc_db_close(g_fc_server.db);
        fc_hashtable_destroy(&g_fc_server.ht_as);
        // fc_hashtable_destroy(&g_fc_server.ht_prefix);
        printf("bye bye!\n");
        exit(EXIT_SUCCESS);
    }
}

    int
fc_server_create(void)
{
    FC_node_as_t meta;
    FC_ht_node_as_t *node;

    fc_db_init(&g_fc_server.db);

    meta.asn = g_fc_server.local_asn;
    node = htbl_meta_find(&g_fc_server.ht_as, &meta);

    if (node)
    {
        if ((g_fc_server.fc_bgpd_ctx = ncs_create(g_fc_server.prog_name, TCP_PROTO))
                == NULL)
        {
            printf("create bgpd ncs failed\n");
            exit(-ENOMEM);
        }

        ncs_setup(g_fc_server.fc_bgpd_ctx, g_fc_server.prog_addr, FC_PORT, NULL, 0);
        ncs_timeout(g_fc_server.fc_bgpd_ctx, 10, -1);
        ncs_setkeepalive(g_fc_server.fc_bgpd_ctx, 10);
        ncs_server_enable(g_fc_server.fc_bgpd_ctx);
        ncs_server_register(g_fc_server.fc_bgpd_ctx, fc_server_handler);
        ncs_manager_start(g_fc_server.fc_bgpd_ctx);
    }

    printf("fc_server : %d is ready!!!\n", g_fc_server.local_asn);

    return 0;
}

    static int
fc_bm_sent_to_peer(const char *addr, const FC_msg_bm_t *bm,
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

    static inline int
fc_asn_is_offpath(u32 asn, const FC_msg_bm_t *bm)
{
    int i = 0;

    for (i=0; i<bm->fc_num; ++i)
    {
        if (asn == bm->fclist[i].previous_asn
            || asn == bm->fclist[i].current_asn
            || asn == bm->fclist[i].nexthop_asn)
        {
            return 0;
        }
    }

    return 1;
}

    static int
fc_bm_find_server(uint32_t asn, char *ifaddr, char *ifname)
{
    FC_node_as_t meta;
    FC_ht_node_as_t *node;

    meta.asn = asn;
    node = htbl_meta_find(&g_fc_server.ht_as, &meta);

    if (node)
    {
        memcpy(ifaddr, node->acs.ipv4[0].ifaddr,
                strlen(node->acs.ipv4[0].ifaddr));
        if (ifname)
        {
            memcpy(ifname, node->acs.ipv4[0].ifname,
                    strlen(node->acs.ipv4[0].ifname));
        }
        return 0;
    }

    return -1;
}

    static int
fc_bm_broadcast_to_peer(ncs_ctx_t *ctx, const FC_msg_bm_t *bm, char *buffer,
        int bufferlen)
{
    printf("broadcast to peers start\n");
    int i = 0, ret = 0;
    u32 asn = 0;
    FC_node_as_t meta = {0};
    char ifaddr[INET6_ADDRSTRLEN] = {0};

    for (i=0; i<g_fc_server.asns_num; ++i)
    {
        asn = g_fc_server.asns[i];
        if (g_fc_server.local_asn == asn)
        {
            continue;
        }

        meta.asn = asn;
        FC_ht_node_as_t *node = htbl_meta_find(&g_fc_server.ht_as, &meta);

        if (node)
        {
            // offpath
            if (fc_asn_is_offpath(asn, bm))
            {
                printf("sent to offpath node: %d->remote_addr: %s\n",
                        node->asn, ctx->remote_addr);
                ret = fc_bm_find_server(asn, ifaddr, NULL);
                if (ret == 0)
                {
                    printf("remote-acs addr: %s\n", ifaddr);
                    fc_bm_sent_to_peer(ifaddr, bm, buffer, bufferlen);
                } else
                {
                    printf("Error: cannot find acs\n");
                }
            }
            // onpath
            else
            {
                printf("sent to onpath node: %d->remote_addr: %s\n",
                        node->asn, ctx->remote_addr);
                ret = fc_bm_find_server(asn, ifaddr, NULL);
                if (ret == 0)
                {
                    printf("remote-acs addr: %s\n", ifaddr);
                    fc_bm_sent_to_peer(ifaddr, bm, buffer, bufferlen);
                } else
                {
                    printf("Error: cannot find acs\n");
                }
            }
        }
    }
    /*
    for (i=0; i<bm->fc_num; ++i)
    {
        // TODO wether asn is in aspath
        meta.asn = bm->fclist[i].current_asn;
        FC_ht_node_as_t *node = htbl_meta_find(&g_fc_server.ht_as,
                &meta);
        if (node)
        {
            if (g_fc_server.local_asn != node->asn)
            {
                printf("sent to %d\n", node->asn);
                fc_bm_sent_to_peer(node->acs.ipv4,
                        bm, buffer, bufferlen);
            }
        }
    }
    */

    printf("broadcast to peers done\n");
    return 0;
}

    int
fc_server_pubkey_handler(ncs_ctx_t *ctx, const char *buff, int len)
{
    return 0;
}

    static int
fc_bm_verify_fc(FC_msg_bm_t *bm)
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
        ret = fc_ecdsa_verify(g_fc_server.pubkey, msg, msglen,
                bm->fclist[i].sig, bm->fclist[i].siglen);
        switch (ret)
        {
        case 1:
            printf("verify fc %d ok\n", i);
            break;
        case 0:
            printf("verify fc %d failed\n", i);
            break;
        default:
            printf("verify fc %d error\n", i);
            break;
        }
    }
    return 0;
}

    static int
fc_gen_acl(ncs_ctx_t *ctx, FC_msg_bm_t *bm)
{
    int i = 0, j = 0, ret = 0;
    int flag_offpath = 0;
    char ifaddr[INET6_ADDRSTRLEN] = {0}, ifname[FC_MAX_SIZE] = {0};
    char saddr[INET6_ADDRSTRLEN] = {0};
    char daddr[INET6_ADDRSTRLEN] = {0};
    u32 asn = 0;

    asn = bm->fclist[0].current_asn;
    if (strcmp("127.0.0.1", ctx->remote_addr) != 0)
    {
        asn = bm->fclist[0].nexthop_asn;
    }

    ret = fc_bm_find_server(asn, ifaddr, ifname);
    if (ret < 0)
    {
        printf("ERROR: there is no such asn: %u\n", asn);
    }
    printf("-=+=-# ifaddr %s, ifname %s #-=+=-\n", ifaddr, ifname);
    flag_offpath = fc_asn_is_offpath(g_fc_server.local_asn, bm);

    inet_ntop(AF_INET, &(((struct sockaddr_in*)&(bm->dst_ip[0].ip))->sin_addr),
            daddr, (socklen_t)sizeof(daddr));

    for (i=0; i<bm->src_ip_num; ++i)
    {
        // TODO ipv6
        inet_ntop(AF_INET, &(((struct sockaddr_in*)&(bm->src_ip[i].ip))->sin_addr),
            saddr, (socklen_t)sizeof(saddr));
        char cmd[1000] = {0};
        if (flag_offpath) // filter: s->d
        {
            for (j=FC_NFT_FILTER_CHAIN_START; j<FC_NFT_FILTER_CHAIN_END; ++j)
            {
                sprintf(cmd, "nft add rule inet filter %s "
                        "ip saddr %s/%d ip daddr %s/%d drop",
                        g_fc_nft_chains[j],
                        saddr, bm->src_ip[0].prefix_length,
                        daddr, bm->dst_ip[0].prefix_length);
                ret = system(cmd);
                // printf("ret = %d, cmd: %s\n", ret, cmd);
            }
        } else // filter: !a->d
        {
            for (j=0; j<g_fc_server.nics_num; ++j)
            {
                if (strcmp(g_fc_server.nics[j], ifname))
                {
                    /*
                    // sudo nft add rule inet filter output oif ens36 \
                    //      ip saddr 192.168.88.131 ip daddr 192.168.88.132 drop
                    //      */
                    if (bm->fclist[0].nexthop_asn == g_fc_server.local_asn)
                    {
                        sprintf(cmd, "nft add rule inet filter %s "
                                "oifname %s ip saddr %s/%d ip daddr %s/%d drop",
                                g_fc_nft_chains[FC_NFT_FILTER_CHAIN_OUTPUT],
                                g_fc_server.nics[j],
                                saddr, bm->src_ip[0].prefix_length,
                                daddr, bm->dst_ip[0].prefix_length);
                    } else
                    {
                        sprintf(cmd, "nft add rule inet filter %s "
                                "iifname %s ip saddr %s/%d ip daddr %s/%d drop",
                                bm->fc_num > 1 ?
                                g_fc_nft_chains[FC_NFT_FILTER_CHAIN_FORWARD]
                                : g_fc_nft_chains[FC_NFT_FILTER_CHAIN_INPUT],
                                g_fc_server.nics[j],
                                saddr, bm->src_ip[0].prefix_length,
                                daddr, bm->dst_ip[0].prefix_length);
                    }
                    ret = system(cmd);
                    // printf("ret = %d, cmd: %s\n", ret, cmd);
                }
            }
        }
    }

    return 0;
}


// buff is starting from bm's ipversion
// msg_type: is broadcast msg
    int
fc_server_bm_handler(ncs_ctx_t *ctx, char *buffer, int bufferlen, int msg_type)
{
    // remove header
    char buff_new_msg[BUFSIZ] = {0};
    memcpy(buff_new_msg, buffer, bufferlen);
    char *buff = buff_new_msg + FC_HDR_GENERAL_LENGTH;

    u32 i = 0;
    FC_msg_bm_t bm = {0};
    int cur = 0;
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
        printf("Not supported now: %d\n", buff[0]);
        return 0;
    } else
    {
        printf("Not supported now: %d\n", buff[0]);
        return -1;
    }

    cur += FC_HDR_BM_FIX_LENGTH;
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
            struct sockaddr_in* addr = (struct sockaddr_in*) &bm.src_ip[i].ip;
            memcpy(&(addr->sin_addr),
                    buff+cur, sizeof(struct in_addr));
        } else
        {
            struct sockaddr_in6* addr = (struct sockaddr_in6*) &bm.src_ip[i].ip;
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
            struct sockaddr_in* addr = (struct sockaddr_in*) &bm.dst_ip[i].ip;
            memcpy(&(addr->sin_addr),
                    buff+cur, sizeof(struct in_addr));
        } else
        {
            struct sockaddr_in6* addr = (struct sockaddr_in6*) &bm.dst_ip[i].ip;
            memcpy(&(addr->sin6_addr),
                    buff+cur, sizeof(struct in6_addr));
        }
        memcpy(&bm.dst_ip[i].prefix_length, buff+cur+ip_len, 1);
        cur += ip_len + 1;
    }

    // fclist
    for (i=0; i<bm.fc_num; ++i)
    {
        memcpy(&bm.fclist[i], buff+cur, FC_HDR_FC_FIX_LENGTH);
        cur += FC_HDR_FC_FIX_LENGTH;
        bm.fclist[i].previous_asn = ntohl(bm.fclist[i].previous_asn);
        bm.fclist[i].current_asn = ntohl(bm.fclist[i].current_asn);
        bm.fclist[i].nexthop_asn = ntohl(bm.fclist[i].nexthop_asn);
        bm.fclist[i].siglen = ntohs(bm.fclist[i].siglen);
        memcpy(bm.fclist[i].sig, buff+cur, bm.fclist[i].siglen);
        cur += bm.fclist[i].siglen;

        printf("3 asn: %d, %d, %d, siglen: %d\n", bm.fclist[i].previous_asn,
                bm.fclist[i].current_asn, bm.fclist[i].nexthop_asn,
                bm.fclist[i].siglen);

        if (bm.fclist[i].nexthop_asn == bm.fclist[i].previous_asn)
        {
            printf("not needed fclist\n");
            return -1;
        }
    }

    ret = fc_bm_verify_fc(&bm);
    FC_ASSERT_RET(ret);

    // TODO need read from g_fc_server.
    // ski -- for signature
    memset(bm.ski, 0, FC_SKI_LENGTH);

    // signature to be signed and verified
    // THIS is in network byte order
    memcpy(msg, buff, cur);

    if (msg_type == FC_MSG_BGPD)
    {
        // add signature for sending to peers
        fc_ecdsa_sign(g_fc_server.prikey, msg, cur,
                &sigbuff, &sigbufflen);
        memcpy(buff+cur+FC_SKI_LENGTH, sigbuff, sigbufflen);
        bm.siglen = sigbufflen;
        sigbufflen = htons(sigbufflen);
        memcpy(&buff[FC_HDR_BM_SIGLEN_POS], &sigbufflen, sizeof(bm.siglen));
        memcpy(bm.signature, sigbuff, bm.siglen);
        OPENSSL_free(sigbuff);
        // broadcast to onpath nodes
        buff_new_msg[1] = FC_MSG_BC;  // type: bc msg
        fc_bm_broadcast_to_peer(ctx, &bm, buff_new_msg,
                FC_HDR_GENERAL_LENGTH+cur+FC_SKI_LENGTH+bm.siglen);
    } else if (msg_type == FC_MSG_BC)
    {
        // verify and remove signature
        // SIGLEN MUST be 0 when verify SIGNATURE
        memset(&msg[FC_HDR_BM_SIGLEN_POS], 0, sizeof(16));
        memcpy(bm.signature, buff+cur+FC_SKI_LENGTH, bm.siglen);
        ret = fc_ecdsa_verify(g_fc_server.pubkey, msg, cur,
                bm.signature, bm.siglen);
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
    fc_gen_acl(ctx, &bm);
    fc_db_write_bm(&bm);

    return 0;
}

    int
fc_server_handler(ncs_ctx_t *ctx)
{
    int bufflen = 0;
    int recvlen = 0;
    char buff[BUFSIZ];

    memset(buff, 0, BUFSIZ);
    recvlen = ncs_server_recv(ctx, buff, BUFSIZ);
    memcpy(&bufflen, &buff[2], sizeof(u16));
    bufflen = ntohs(bufflen);

    printf("Accept from: %s:%d\n", ctx->remote_addr, ctx->remote_port);
    printf("bufflen: %d, recvlen: %d\n", bufflen, recvlen);
    /*
    while (bufflen > recvlen)
    {
        recvlen += ncs_server_recv(ctx, buff+recvlen,
                bufflen-recvlen);
    }
    */

    if (buff[0] == FC_VERSION)
    {
        switch (buff[1])
        {
        case 1: // pubkey
            printf("Not support pubkey\n");
            // TODO length
            fc_server_pubkey_handler(ctx, buff, recvlen);
            return 0;
        case 2: // bm
            // TODO length
            fc_server_bm_handler(ctx, buff, recvlen, FC_MSG_BGPD);
            break;
        case 3: // broadcast msg
            // TODO length
            fc_server_bm_handler(ctx, buff, recvlen, FC_MSG_BC);
            break;
        default:
            printf("Not support %d\n", buff[0]);
            return -1;
        }
    } else {
        printf("recvlen: %d\n", recvlen);
        if (recvlen > 1)
        {
            printf("FC HDR VERSION: %d\n", buff[0]);
        }
    }

    printf("#################################################\n\n");

    ncs_client_stop(ctx);

    return 0;
}

    static inline void
fc_help(void)
{
    printf("  -h                   print this message.\n");
    printf("  -f <config.json>    specify the location of config.json\n");
}

    static void
fc_parse_args(int argc, char **argv)
{
    int opt = 0;

    while ((opt = getopt(argc, argv, "f:h")) > 0)
    {
        switch(opt)
        {
        case 'f':
            memcpy(g_fc_server.fname, optarg, strlen(optarg));
            break;
        case 'h':
            fc_help();
            exit(EXIT_SUCCESS);
        default:
            fprintf(stderr, "unknown opt: %d\n", opt);
            fc_help();
            exit(EXIT_FAILURE);
        }
    }

    if ( ! g_fc_server.fname || strlen(g_fc_server.fname) == 0)
    {
        const char *pfname = "/etc/frr/assets/config.json";
        memcpy(g_fc_server.fname, pfname, strlen(pfname));
    }
}

    int
fc_main()
{
    g_fc_server.prog_name = "fcserver";
    g_fc_server.prog_addr = "0.0.0.0";

    fc_hashtable_create(&g_fc_server.ht_as, &g_fc_htbl_as_ops);

    fc_read_config();

    if (g_fc_server.log_mode > FC_LOG_LEVEL_INFO)
    {
        htbl_display(&g_fc_server.ht_as);
    }

    diag_init(g_fc_server.prog_name);
    diag_level_set(g_fc_server.log_mode);

    fc_init_crypto_env(&g_fc_server);

    fc_server_create();

    signal(SIGINT, fc_server_destroy);

    while (1)
    {
        sleep(1);
    }

    return 0;
}

    int
main(int argc, char **argv)
{
    fc_parse_args(argc, argv);
    fc_main();

    return 0;
}
