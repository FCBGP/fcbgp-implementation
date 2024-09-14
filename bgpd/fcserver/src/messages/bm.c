/**
 * @file bm.c
 * @author basilguo@163.com
 * @brief
 * @version 0.0.1
 * @date 2024-09-14
 *
 * @copyright Copyright (c) 2021 - 2024
 */

#ifdef __cplusplus
extern "C"
{
#endif /* __cplusplus */

#include "dbutils.h"
#include "defines.h"
#include "fcserver.h"
#include "hashutils.h"
#include "libdiag.h"
#include "sigutils.h"
#include <stdio.h>
#include <stdlib.h>

    static int
    fc_bm_sent_to_peer(const char *addr, const FC_msg_bm_t *bm,
                       unsigned char *buffer, int bufferlen)
    {
        int ret = 0;
        int sockfd = 0;
        int len = 0;
        struct sockaddr_in sockaddr;

        if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
        {
            DIAG_ERROR("socket(), %s\n", strerror(errno));
            return -1;
        }
        sockaddr.sin_family = AF_INET;
        sockaddr.sin_port = htons(g_fc_server.listen_port);
        inet_pton(AF_INET, addr, &sockaddr.sin_addr);
        if ((ret = connect(sockfd, (struct sockaddr *)&sockaddr,
                           sizeof(sockaddr))) < 0)
        {
            DIAG_ERROR("connect(), %s\n", strerror(errno));
            return -1;
        }

        while (len != bufferlen)
        {
            len = len + send(sockfd, buffer + len, bufferlen - len, 0);
            DIAG_INFO("len = %d, bufferlen = %d\n", len, bufferlen);
        }

        close(sockfd);

        return 0;
    }

    int fc_bm_find_server(uint32_t asn, char *ifaddr, char *ifname)
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
    fc_bm_broadcast_to_peer(int clisockfd, const FC_msg_bm_t *bm,
                            unsigned char *buffer, int bufferlen)
    {
        DIAG_INFO("broadcast to peers start\n");
        int i = 0, ret = 0;
        u32 asn = 0;

        for (i = 0; i < g_fc_server.asns_num; ++i)
        {
            FC_node_as_t meta = {0};
            char ifaddr[INET6_ADDRSTRLEN] = {0};

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
                    DIAG_INFO("sent to offpath node: %d\n", node->asn);
                    ret = fc_bm_find_server(asn, ifaddr, NULL);
                    if (ret == 0)
                    {
                        DIAG_INFO("remote-acs addr: %s\n", ifaddr);
                        fc_bm_sent_to_peer(ifaddr, bm, buffer, bufferlen);
                    }
                    else
                    {
                        DIAG_INFO("Error: cannot find acs\n");
                    }
                }
                // onpath
                else
                {
                    DIAG_INFO("sent to onpath node: %d\n", node->asn);
                    ret = fc_bm_find_server(asn, ifaddr, NULL);
                    if (ret == 0)
                    {
                        DIAG_INFO("remote-acs addr: %s\n", ifaddr);
                        fc_bm_sent_to_peer(ifaddr, bm, buffer, bufferlen);
                    }
                    else
                    {
                        DIAG_INFO("Error: cannot find acs\n");
                    }
                }
            }
        }

#if 0
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
                DIAG_INFO("sent to %d\n", node->asn);
                fc_bm_sent_to_peer(node->acs.ipv4,
                        bm, buffer, bufferlen);
            }
        }
    }
#endif

        DIAG_INFO("broadcast to peers done\n");
        return 0;
    }

    static int
    fc_bm_verify_fc(FC_msg_bm_t *bm)
    {
        u8 msg[FC_BUFF_SIZE];
        int ret = 0;
        int msglen = 0;
        int i = 0, j = 0;
        u32 previous_asn = 0, current_asn = 0, nexthop_asn = 0;

        for (i = 0; i < bm->fc_num; ++i)
        {
            memset(msg, 0, FC_BUFF_SIZE);
            msglen = 0;
            // hash(prev_asn, curr_asn, next_asn, dst_ip, prefixlen)
            // asn
            previous_asn = htonl(bm->fclist[i].previous_asn);
            current_asn = htonl(bm->fclist[i].current_asn);
            nexthop_asn = htonl(bm->fclist[i].nexthop_asn);
            memcpy(msg + msglen, &previous_asn, sizeof(u32));
            msglen += sizeof(u32);
            memcpy(msg + msglen, &current_asn, sizeof(u32));
            msglen += sizeof(u32);
            memcpy(msg + msglen, &nexthop_asn, sizeof(u32));
            msglen += sizeof(u32);
            // dst_ip
            for (j = 0; j < bm->dst_ip_num; ++j)
            {
                if (bm->ipversion == IPV4)
                {
                    u32 ip4 = ((struct sockaddr_in *)&(bm->dst_ip[j].ip))->sin_addr.s_addr;
                    memcpy(msg + msglen, &ip4, IP4_LENGTH);
                    msglen += IP4_LENGTH;
                }
                else
                {
                    struct sockaddr_in6 *ip6;
                    ip6 = (struct sockaddr_in6 *)&(bm->dst_ip[j].ip);
                    memcpy(msg + msglen, &(ip6->sin6_addr), IP6_LENGTH);
                    msglen += IP6_LENGTH;
                }
                memcpy(msg + msglen, &bm->dst_ip[j].prefix_length, 1);
                msglen += 1;
            }

            FC_ht_node_as_t *node;
            FC_node_as_t meta = {0};
            meta.asn = bm->fclist[i].current_asn;
            node = htbl_meta_find(&g_fc_server.ht_as, &meta);

            DIAG_INFO("asn: %u, ", node->asn);
            fc_print_bin("ski", node->ski, FC_SKI_LENGTH);

            ret = fc_ecdsa_verify(node->pubkey, msg, msglen,
                                  bm->fclist[i].sig, bm->fclist[i].siglen);
            switch (ret)
            {
            case 1:
                DIAG_INFO("verify fc %d ok\n", i);
                break;
            case 0:
                DIAG_ERROR("verify fc %d failed\n", i);
                break;
            default:
                DIAG_ERROR("verify fc %d error\n", i);
                break;
            }
        }
        return 0;
    }

    static void
    fc_bm_print(const FC_msg_bm_t *bm)
    {
        int i = 0;
        struct sockaddr_in *in4 = NULL;
        struct sockaddr_in6 *in6 = NULL;
        char ipstr[INET6_ADDRSTRLEN];
        DIAG_INFO("bm version: %d\n", bm->bmversion);
        DIAG_INFO("ip version: %d\n", bm->ipversion);
        DIAG_INFO("flags: %02X\n", bm->flags);
        DIAG_INFO("algoid: %d\n", bm->algoid);
        DIAG_INFO("src ip prefix num: %d\n", bm->src_ip_num);
        DIAG_INFO("dst ip prefix num: %d\n", bm->dst_ip_num);
        DIAG_INFO("fc num: %d\n", bm->fc_num);
        DIAG_INFO("siglen: %d\n", bm->siglen);
        DIAG_INFO("local_asn: %08X\n", bm->local_asn);
        DIAG_INFO("version: %08X\n", bm->version);
        DIAG_INFO("subversion: %08X\n", bm->subversion);

        DIAG_INFO("src ip prefix:\n");
        for (i = 0; i < bm->src_ip_num; ++i)
        {
            memset(ipstr, 0, INET6_ADDRSTRLEN);
            DIAG_INFO("  idx: %d, ", i);
            switch (bm->ipversion)
            {
            case IPV4:
                in4 = (struct sockaddr_in *)&bm->src_ip[i].ip;
                inet_ntop(AF_INET,
                          &in4->sin_addr,
                          ipstr, sizeof(struct sockaddr_in));
                DIAG_INFO("%s/%d\n", ipstr, bm->src_ip[i].prefix_length);
                break;
            case IPV6:
                in6 = (struct sockaddr_in6 *)&bm->src_ip[i].ip;
                inet_ntop(AF_INET6,
                          &in6->sin6_addr,
                          ipstr, sizeof(struct sockaddr_in6));
                DIAG_INFO("%s/%d\n", ipstr, bm->src_ip[i].prefix_length);
                break;
            }
        }
        DIAG_INFO("dst ip prefix:\n");
        for (i = 0; i < bm->dst_ip_num; ++i)
        {
            memset(ipstr, 0, INET6_ADDRSTRLEN);
            DIAG_INFO("  idx: %d, ", i);
            switch (bm->ipversion)
            {
            case IPV4:
                inet_ntop(AF_INET,
                          &((struct sockaddr_in *)&bm->dst_ip[i].ip)->sin_addr,
                          ipstr, sizeof(struct sockaddr_in));
                DIAG_INFO("%s/%d\n", ipstr, bm->dst_ip[i].prefix_length);
                break;
            case IPV6:
                inet_ntop(AF_INET6,
                          &((struct sockaddr_in6 *)&bm->dst_ip[i].ip)->sin6_addr,
                          ipstr, sizeof(struct sockaddr_in6));
                DIAG_INFO("%s/%d\n", ipstr, bm->dst_ip[i].prefix_length);
                break;
            }
        }
        DIAG_INFO("fc list:\n");
        for (i = 0; i < bm->fc_num; ++i)
        {
            DIAG_INFO("  idx: %d, 3 asn: %d, %d, %d, algo-id: %d, flags: %d, siglen: %d, ",
                      i,
                      bm->fclist[i].previous_asn,
                      bm->fclist[i].current_asn,
                      bm->fclist[i].nexthop_asn,
                      bm->fclist[i].algo_id,
                      bm->fclist[i].flags,
                      bm->fclist[i].siglen);
            fc_print_bin("sig", bm->fclist[i].sig, bm->fclist[i].siglen);
        }

        fc_print_bin("bin", bm->ski, FC_SKI_LENGTH);
    }

    static int
    fc_msg_bm_decap_fixed(FC_msg_bm_t *bm, const unsigned char *buff, int currlen)
    {
        memcpy(bm, buff, FC_HDR_BM_FIX_LENGTH);
        currlen += FC_HDR_BM_FIX_LENGTH;

        bm->src_ip_num = ntohs(bm->src_ip_num);
        bm->dst_ip_num = ntohs(bm->dst_ip_num);
        bm->fc_num = ntohs(bm->fc_num);
        bm->siglen = ntohs(bm->siglen);
        bm->local_asn = ntohl(bm->local_asn);
        bm->version = ntohl(bm->version);
        bm->subversion = ntohl(bm->subversion);

        return currlen;
    }

    static int
    fc_msg_bm_decap_srcip(FC_msg_bm_t *bm, const unsigned char *buff,
                          int currlen, int ip_addr_len)
    {
        int i = 0;
        for (i = 0; i < bm->src_ip_num; ++i)
        {
            bm->src_ip[i].prefix_length = *(buff + currlen + ip_addr_len);
            switch (bm->ipversion)
            {
            case IPV4:
                struct sockaddr_in *in4 = (struct sockaddr_in *)&bm->src_ip[i].ip;
                in4->sin_family = AF_INET;
                memcpy(&(in4->sin_addr), buff + currlen, ip_addr_len);
                //    in4->sin_addr.s_addr = ntohl(in4->sin_addr.s_addr);
                break;
            case IPV6:
                struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)&bm->src_ip[i].ip;
                in6->sin6_family = AF_INET6;
                memcpy(&(in6->sin6_addr), buff + currlen, ip_addr_len);
                break;
            default:
                break;
            }
            currlen += ip_addr_len + 1;
        }

        return currlen;
    }

    static int
    fc_msg_bm_decap_dstip(FC_msg_bm_t *bm, const unsigned char *buff,
                          int currlen, int ip_addr_len)
    {
        int i = 0;
        for (i = 0; i < bm->dst_ip_num; ++i)
        {
            bm->dst_ip[i].prefix_length = *(buff + currlen + ip_addr_len);
            switch (bm->ipversion)
            {
            case IPV4:
                struct sockaddr_in *in4 = (struct sockaddr_in *)&bm->dst_ip[i].ip;
                in4->sin_family = AF_INET;
                memcpy(&(in4->sin_addr), buff + currlen, ip_addr_len);
                //   in4->sin_addr.s_addr = ntohl(in4->sin_addr.s_addr);
                break;
            case IPV6:
                struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)&bm->dst_ip[i].ip;
                memcpy(&(in6->sin6_addr), buff + currlen, ip_addr_len);
                break;
            default:
                break;
            }
            currlen += ip_addr_len + 1;
        }

        return currlen;
    }

    static int
    fc_msg_bm_decap_fclist(FC_msg_bm_t *bm, const unsigned char *buff, int currlen)
    {
        int i = 0;
        for (i = 0; i < bm->fc_num; ++i)
        {
            u16 siglen = 0;
            u32 asn = 0;
            // pasn
            memcpy(&asn, buff + currlen, sizeof(u32));
            currlen += sizeof(u32);
            bm->fclist[i].previous_asn = ntohl(asn);
            // casn
            memcpy(&asn, buff + currlen, sizeof(u32));
            currlen += sizeof(u32);
            bm->fclist[i].current_asn = ntohl(asn);
            // nasn
            memcpy(&asn, buff + currlen, sizeof(u32));
            currlen += sizeof(u32);
            bm->fclist[i].nexthop_asn = ntohl(asn);
            // ski
            memcpy(bm->fclist[i].ski, buff + currlen, FC_SKI_LENGTH);
            currlen += FC_SKI_LENGTH;
            // algo_id
            memcpy(&bm->fclist[i].algo_id, buff + currlen, sizeof(u8));
            currlen += sizeof(u8);
            // flags
            memcpy(&bm->fclist[i].flags, buff + currlen, sizeof(u8));
            currlen += sizeof(u8);
            // siglen
            memcpy(&siglen, buff + currlen, sizeof(u16));
            currlen += sizeof(u16);
            bm->fclist[i].siglen = ntohs(siglen);
            // sig
            memcpy(bm->fclist[i].sig, buff + currlen, bm->fclist[i].siglen);
            currlen += bm->fclist[i].siglen;

            if (bm->fclist[i].nexthop_asn == bm->fclist[i].previous_asn)
            {
                DIAG_INFO("Not needed fclist, 3 asns: %08X %08X %08X\n",
                          bm->fclist[i].previous_asn,
                          bm->fclist[i].current_asn,
                          bm->fclist[i].nexthop_asn);
                return -1;
            }
        }

        return currlen;
    }

    static int
    fc_msg_bm_bgpd_handler(int clisockfd, FC_msg_bm_t *bm, unsigned char *buffer,
                           const unsigned char *msg,
                           unsigned char *buff, int currlen)
    {
        unsigned char *sigbuff = NULL;
        unsigned int sigbufflen = 0;

        // TODO verify signature from bgpd

        // add signature for sending to peers
        DIAG_INFO("prikey_fname: %s\n", g_fc_server.prikey_fname);
        fc_ecdsa_sign(g_fc_server.prikey, msg, currlen, &sigbuff, &sigbufflen);
        memcpy(bm->ski, g_fc_server.ski, FC_SKI_LENGTH);
        memcpy(buff + currlen, g_fc_server.ski, FC_SKI_LENGTH);
        currlen += FC_SKI_LENGTH;
        memcpy(buff + currlen, sigbuff, sigbufflen);
        currlen += sigbufflen;
        bm->siglen = sigbufflen;
        sigbufflen = htons(sigbufflen);
        memcpy(&buff[FC_HDR_BM_SIGLEN_POS], &sigbufflen, sizeof(bm->siglen));
        memcpy(bm->signature, sigbuff, bm->siglen);
        OPENSSL_free(sigbuff);

        // broadcast to onpath nodes
        buffer[1] = FC_MSG_BC;
        u16 new_length = htons(currlen);
        memcpy(&buffer[2], &new_length, sizeof(u16));
        fc_bm_broadcast_to_peer(clisockfd, bm, buffer, FC_HDR_GENERAL_LENGTH + currlen);
        return 0;
    }

    static int
    fc_msg_bm_bc_handler(FC_msg_bm_t *bm, const unsigned char *msg,
                         const unsigned char *buff, int currlen)
    {
        int ret = 0;

        DIAG_INFO("### Verify BM Signature Start ###\n");
        // verify and remove signature
        memcpy(bm->ski, buff + currlen, FC_SKI_LENGTH);
        memcpy(bm->signature, buff + currlen + FC_SKI_LENGTH, bm->siglen);

        DIAG_INFO("bm asn: %u, ", bm->local_asn);
        fc_print_bin("ski", bm->ski, FC_SKI_LENGTH);

        FC_ht_node_as_t *node;
        FC_node_as_t meta = {0};
        meta.asn = bm->local_asn;
        node = htbl_meta_find(&g_fc_server.ht_as, &meta);
        DIAG_INFO("node asn: %u, ", node->asn);
        fc_print_bin("ski", node->ski, FC_SKI_LENGTH);

        ret = fc_ecdsa_verify(node->pubkey,
                              msg, currlen, bm->signature, bm->siglen);

        switch (ret)
        {
        case 1:
            DIAG_INFO("verify sig ok\n");
            break;
        case 0:
            DIAG_ERROR("verify sig failed\n");
            break;
        default:
            DIAG_ERROR("verify sig error\n");
            break;
        }

        DIAG_INFO("### Verify BM Signature End ###\n");

        return ret;
    }

    // buff is starting from bm's ipversion
    // msg_type: is broadcast msg
    int fc_server_bm_handler(int clisockfd, unsigned char *buffer,
                             int bufferlen, int msg_type)
    {
        FC_msg_bm_t bm = {0};
        unsigned char msg[FC_BUFF_SIZE] = {0};
        int curlen = 0, ret = 0, ip_addr_len = 0;
        unsigned char *buff = buffer + FC_HDR_GENERAL_LENGTH;

        // bmversion
        switch (buff[0])
        {
        case FC_MSG_BM_VERSION: // current bm version
            break;
        default:
            DIAG_ERROR("BM version %d is not supported\n", buff[0]);
            return -1;
        }

        // ipversion
        switch (buff[1])
        {
        case IPV4: // ipv4
            ip_addr_len = IP4_LENGTH;
            break;
        case IPV6: // ipv6
            ip_addr_len = IP6_LENGTH;
            break;
        default:
            DIAG_ERROR("IP version %d is not supported now\n", buff[1]);
            return -1;
        }

        curlen = fc_msg_bm_decap_fixed(&bm, buff, curlen);
        curlen = fc_msg_bm_decap_srcip(&bm, buff, curlen, ip_addr_len);
        curlen = fc_msg_bm_decap_dstip(&bm, buff, curlen, ip_addr_len);
        curlen = fc_msg_bm_decap_fclist(&bm, buff, curlen);
        if (curlen == -1)
        {
            return -1;
        }

        ret = fc_bm_verify_fc(&bm);
        FC_ASSERT_RET(ret);

        // signature to be signed and verified
        // THIS is in network byte order
        memcpy(msg, buff, curlen);
        // SIGLEN MUST be 0 when sign/verify SIGNATURE
        memset(&msg[FC_HDR_BM_SIGLEN_POS], 0, sizeof(16));

        switch (msg_type)
        {
        case FC_MSG_BGPD:
            fc_msg_bm_bgpd_handler(clisockfd, &bm, buffer, msg, buff, curlen);
            break;
        case FC_MSG_BC:
            fc_msg_bm_bc_handler(&bm, msg, buff, curlen);
            break;
        }

        fc_bm_print(&bm);
        fc_acl_gen(clisockfd, &bm);
        fc_db_write_bm(&bm);

        return 0;
    }

#ifdef __cplusplus
}
#endif /* __cplusplus */
