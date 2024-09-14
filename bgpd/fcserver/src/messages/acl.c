/**
 * @file acl.c
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
#include "nftutils.h"
#include "pyutils.h"
#include "sigutils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

    static int
    fc_acl_gen_linux(int clisockfd, const FC_msg_bm_t *bm)
    {
        int i = 0, j = 0, ret = 0;
        bool is_offpath = false;
        char ifaddr[INET6_ADDRSTRLEN] = {0}, ifname[FC_MAX_SIZE] = {0};
        char saddr[INET6_ADDRSTRLEN] = {0};
        char daddr[INET6_ADDRSTRLEN] = {0};
        u32 asn = 0;

        asn = bm->fclist[0].current_asn;
        char ipbuf[INET6_ADDRSTRLEN] = {0};
        struct sockaddr_in6 sockaddr;

        fc_sock_get_addr_from_peer_fd(clisockfd, (struct sockaddr *)&sockaddr,
                                      ipbuf, INET6_ADDRSTRLEN);
        if (strcmp("127.0.0.1", ipbuf) != 0)
        {
            asn = bm->fclist[0].nexthop_asn;
        }

        ret = fc_bm_find_server(asn, ifaddr, ifname);
        if (ret < 0)
        {
            DIAG_ERROR("ERROR: there is no such asn: %u\n", asn);
        }
        DIAG_INFO("-=+=-# ifaddr %s, ifname %s #-=+=-\n", ifaddr, ifname);
        is_offpath = fc_asn_is_offpath(g_fc_server.local_asn, bm);

        inet_ntop(AF_INET, &(((struct sockaddr_in *)&(bm->dst_ip[0].ip))->sin_addr),
                  daddr, (socklen_t)sizeof(daddr));

        for (i = 0; i < bm->src_ip_num; ++i)
        {
            // TODO ipv6
            inet_ntop(AF_INET, &(((struct sockaddr_in *)&(bm->src_ip[i].ip))->sin_addr),
                      saddr, (socklen_t)sizeof(saddr));
            char cmd[1000] = {0};
            if (is_offpath) // filter: s->d
            {
                for (j = FC_NFT_FILTER_CHAIN_START; j < FC_NFT_FILTER_CHAIN_END; ++j)
                {
                    sprintf(cmd, "nft add rule inet filter %s "
                                 "ip saddr %s/%d ip daddr %s/%d drop",
                            g_fc_nft_chains[j],
                            saddr, bm->src_ip[0].prefix_length,
                            daddr, bm->dst_ip[0].prefix_length);
                    ret = system(cmd);
                    // DIAG_INFO("ret = %d, cmd: %s\n", ret, cmd);
                }
            }
            else // filter: !a->d
            {
                for (j = 0; j < g_fc_server.nics_num; ++j)
                {
                    if (strcmp(g_fc_server.nics[j], ifname))
                    {
                        /*
                         * sudo nft add rule inet filter output oif ens36 \
                         *      ip saddr 192.168.88.131 ip daddr 192.168.88.132 drop
                         * */
                        if (bm->fclist[0].nexthop_asn == g_fc_server.local_asn)
                        {
                            sprintf(cmd, "nft add rule inet filter %s "
                                         "oifname %s ip saddr %s/%d ip daddr %s/%d drop",
                                    g_fc_nft_chains[FC_NFT_FILTER_CHAIN_OUTPUT],
                                    g_fc_server.nics[j],
                                    saddr, bm->src_ip[0].prefix_length,
                                    daddr, bm->dst_ip[0].prefix_length);
                        }
                        else
                        {
                            sprintf(cmd, "nft add rule inet filter %s "
                                         "iifname %s ip saddr %s/%d ip daddr %s/%d drop",
                                    bm->fc_num > 1 ? g_fc_nft_chains[FC_NFT_FILTER_CHAIN_FORWARD]
                                                   : g_fc_nft_chains[FC_NFT_FILTER_CHAIN_INPUT],
                                    g_fc_server.nics[j],
                                    saddr, bm->src_ip[0].prefix_length,
                                    daddr, bm->dst_ip[0].prefix_length);
                        }
                        ret = system(cmd);
                        // DIAG_INFO("ret = %d, cmd: %s\n", ret, cmd);
                    }
                }
            }
        }

        return 0;
    }

    static int
    fc_acl_gen_h3c(int clisockfd, const FC_msg_bm_t *bm)
    {
        int ret = 0, fc_index = 0;
        bool is_offpath = true, is_withdraw = false;
        bool is_route_source = false, is_from_bgpd = false;
        bool is_still_loop = true;
        FC_router_info_t *router_info = NULL;
        FC_router_link_info_t *link_info = NULL;
        FC_router_iface_info_t *iface_info = NULL;
        char saddr[INET6_ADDRSTRLEN] = {0};
        char daddr[INET6_ADDRSTRLEN] = {0};
        int sprefixlen = 0, dprefixlen = 0;
        direction_e direction = 0; // 0 for none, 1 for in, 2 for out, 3 for both
        u16 rule_id = 1;           // 1 - 65534, 65535 for autogen by router in h3c
        u32 acl_rule_info_key = 0;

        is_withdraw = (bm->flags & FC_BM_FLAGS_WITHDRAW);

        /*
         * offpath node: deny <src, dst>
         * onpath node: deny <src, dst>
         *      from bgpd: permit link pasn out
         *      route source: permit link nasn in
         *      mid node: permit link to pasn out,
         *                permit link to nasn in
         */
        // from bgpd means this is a onpath node
        is_from_bgpd = (bm->local_asn == g_fc_server.local_asn);

        if (!is_from_bgpd)
        {
            is_offpath = true;
            for (fc_index = 0; fc_index < bm->fc_num; fc_index++)
            {
                if (bm->fclist[fc_index].current_asn == g_fc_server.local_asn)
                {
                    is_offpath = false;
                    break;
                }
            }
        }

        if (!is_offpath)
        {
            int idx = bm->fc_num - 1;
            u32 source_casn = bm->fclist[idx].current_asn;
            is_route_source = (source_casn == g_fc_server.local_asn);
        }

        DIAG_DEBUG("fc-index: %d, from-bgpd? %d, offpath? %d, withdraw? %d\n",
                   fc_index, is_from_bgpd, is_offpath, is_withdraw);

        // maybe can be removed as dst_ip_num is always 1
        for (int i = 0; is_still_loop && i < bm->dst_ip_num; ++i)
        {
            switch (bm->ipversion)
            {
            case IPV4:
                inet_ntop(AF_INET,
                          &(((struct sockaddr_in *)&(bm->dst_ip[i].ip))->sin_addr),
                          daddr, (socklen_t)sizeof(daddr));
                break;
            case IPV6:
                inet_ntop(AF_INET6,
                          &(((struct sockaddr_in6 *)&(bm->dst_ip[i].ip))->sin6_addr),
                          daddr, (socklen_t)sizeof(daddr));
                break;
            }
            dprefixlen = bm->dst_ip[i].prefix_length;
            for (int j = 0; is_still_loop && j < bm->src_ip_num; ++j)
            {
                switch (bm->ipversion)
                {
                case IPV4:
                    inet_ntop(AF_INET,
                              &(((struct sockaddr_in *)&(bm->src_ip[j].ip))->sin_addr),
                              saddr, (socklen_t)sizeof(saddr));
                    break;
                case IPV6:
                    inet_ntop(AF_INET6,
                              &(((struct sockaddr_in6 *)&(bm->src_ip[j].ip))->sin6_addr),
                              saddr, (socklen_t)sizeof(saddr));
                    break;
                }
                sprefixlen = bm->src_ip[j].prefix_length;
                router_info = g_fc_server.routers;

                if (router_info == NULL)
                {
                    DIAG_ERROR("Sorry, there is no router link info.\n");
                    DIAG_ERROR("Have you configured it in configuration file: %s?\n",
                               g_fc_server.config_fname);
                    is_still_loop = false;
                }

                // actually, there may be no so many devices
                while (router_info)
                {
                    link_info = router_info->links;

                    if (link_info == NULL)
                    {
                        DIAG_ERROR("Router (bgpid: %08X) does not hold any link.\n",
                                   router_info->bgpid);
                        is_still_loop = false;
                    }

                    while (link_info)
                    {
                        for (iface_info = link_info->iface_list;
                             iface_info != NULL;
                             iface_info = iface_info->next)
                        {
                            ht_acl_group_info_t *item = NULL;
                            item = mln_hash_search(g_fc_server.ht_acl_group_info,
                                                   &iface_info->iface_index);
                            FC_ASSERT_RETP(item);
                            if (is_offpath) // offpath node
                            {
                                DIAG_INFO("offpath node srcip: %s/%d, dstip: %s/%d, "
                                          "iface_index: %08X, direction: both\n",
                                          saddr, sprefixlen, daddr, dprefixlen,
                                          iface_info->iface_index);

                                if (is_withdraw) // withdraw/del
                                {
                                    //! offpath withdraw acl-in direction
                                    ht_acl_rule_info_t *acl_rule_info = NULL;
                                    ht_acl_rule_info_t *rule =
                                        (ht_acl_rule_info_t *)calloc(1, sizeof(ht_acl_rule_info_t));
                                    rule->ipversion = bm->ipversion;
                                    memcpy(rule->saddr, saddr, INET6_ADDRSTRLEN);
                                    rule->sprefixlen = sprefixlen;
                                    memcpy(rule->daddr, daddr, INET6_ADDRSTRLEN);
                                    rule->dprefixlen = dprefixlen;
                                    rule->rule_id = 0;
                                    rule->direction = FC_TOPO_DIRECTION_NONE;
                                    rule->acl_group_index = item->acl_group_index;
                                    acl_rule_info_key = fnv1a_hash(rule, sizeof(rule));
                                    HASH_FIND_INT(item->ht_acl_rule_info, &acl_rule_info_key, acl_rule_info);

                                    if (acl_rule_info)
                                    {
                                        DIAG_INFO("offpath withdraw acl-in direction, "
                                                  "[%s:%d] group index: %u, "
                                                  "ipversion: %d rule_id: %u, "
                                                  "src prefix: %s/%d, dst prefix: %s/%d, "
                                                  "iface_index: %08X\n",
                                                  __FUNCTION__, __LINE__,
                                                  item->acl_group_index, bm->ipversion,
                                                  acl_rule_info->rule_id,
                                                  saddr, sprefixlen, daddr, dprefixlen,
                                                  iface_info->iface_index);
                                        py_apply_acl(&router_info->py_config,
                                                     item->acl_group_index,
                                                     bm->ipversion,
                                                     is_withdraw,
                                                     acl_rule_info->rule_id,
                                                     saddr, sprefixlen,
                                                     daddr, dprefixlen,
                                                     iface_info->iface_index,
                                                     FC_TOPO_DIRECTION_IN);
                                        HASH_DEL(item->ht_acl_rule_info, acl_rule_info);
                                        free(acl_rule_info);
                                    }
                                    else
                                    {

                                        DIAG_INFO("no such offpath withdraw acl-in direction, "
                                                  "[%s:%d] group index: %u, "
                                                  "ipversion: %d fake rule_id: %u, "
                                                  "src prefix: %s/%d, dst prefix: %s/%d, "
                                                  "iface_index: %08X\n",
                                                  __FUNCTION__, __LINE__,
                                                  item->acl_group_index, bm->ipversion,
                                                  rule_id,
                                                  saddr, sprefixlen, daddr, dprefixlen,
                                                  iface_info->iface_index);
                                    }

                                    //! offpath withdraw acl-out direction
                                    rule->ipversion = bm->ipversion;
                                    memcpy(rule->saddr, saddr, INET6_ADDRSTRLEN);
                                    rule->sprefixlen = sprefixlen;
                                    memcpy(rule->daddr, daddr, INET6_ADDRSTRLEN);
                                    rule->dprefixlen = dprefixlen;
                                    rule->rule_id = 0;
                                    rule->direction = FC_TOPO_DIRECTION_NONE;
                                    rule->acl_group_index = item->acl_group_index;
                                    acl_rule_info_key = fnv1a_hash(rule, sizeof(rule));
                                    HASH_FIND_INT(item->ht_acl_rule_info, &acl_rule_info_key, acl_rule_info);

                                    if (acl_rule_info)
                                    {
                                        DIAG_INFO("offpath withdraw acl-out direction, "
                                                  "[%s:%d] group index: %u, "
                                                  "ipversion: %d rule_id: %u, "
                                                  "src prefix: %s/%d, dst prefix: %s/%d, "
                                                  "iface_index: %08X\n",
                                                  __FUNCTION__, __LINE__,
                                                  item->acl_group_index, bm->ipversion,
                                                  acl_rule_info->rule_id,
                                                  saddr, sprefixlen, daddr, dprefixlen,
                                                  iface_info->iface_index);
                                        py_apply_acl(&router_info->py_config,
                                                     item->acl_group_index,
                                                     bm->ipversion,
                                                     is_withdraw,
                                                     acl_rule_info->rule_id,
                                                     saddr, sprefixlen,
                                                     daddr, dprefixlen,
                                                     iface_info->iface_index,
                                                     FC_TOPO_DIRECTION_OUT);
                                        HASH_DEL(item->ht_acl_rule_info, acl_rule_info);
                                        free(acl_rule_info);
                                    }
                                    else
                                    {
                                        DIAG_INFO("no such offpath withdraw acl-out direction, "
                                                  "[%s:%d] group index: %u, "
                                                  "ipversion: %d fake rule_id: %u, "
                                                  "src prefix: %s/%d, dst prefix: %s/%d, "
                                                  "iface_index: %08X\n",
                                                  __FUNCTION__, __LINE__,
                                                  item->acl_group_index, bm->ipversion,
                                                  rule_id,
                                                  saddr, sprefixlen, daddr, dprefixlen,
                                                  iface_info->iface_index);
                                    }
                                    free(rule);
                                }
                                else // update/add
                                {
                                    //! offpath update acl-in direction
                                    rule_id = ++item->acl_rule_in_id;
                                    DIAG_INFO("offpath update acl-in direction, "
                                              "[%s:%d] group index: %u, "
                                              "ipversion: %d rule_id: %u, "
                                              "src prefix: %s/%d, dst prefix: %s/%d, "
                                              "iface_index: %08X\n",
                                              __FUNCTION__, __LINE__, item->acl_group_index,
                                              bm->ipversion, rule_id,
                                              saddr, sprefixlen, daddr, dprefixlen,
                                              iface_info->iface_index);
                                    py_apply_acl(&router_info->py_config,
                                                 item->acl_group_index,
                                                 bm->ipversion,
                                                 is_withdraw, rule_id,
                                                 saddr, sprefixlen,
                                                 daddr, dprefixlen,
                                                 iface_info->iface_index,
                                                 FC_TOPO_DIRECTION_IN);
                                    ht_acl_rule_info_t *acl_rule_info =
                                        (ht_acl_rule_info_t *)calloc(1, sizeof(ht_acl_rule_info_t));
                                    acl_rule_info->ipversion = bm->ipversion;
                                    memcpy(acl_rule_info->saddr, saddr, INET6_ADDRSTRLEN);
                                    acl_rule_info->sprefixlen = sprefixlen;
                                    memcpy(acl_rule_info->daddr, daddr, INET6_ADDRSTRLEN);
                                    acl_rule_info->dprefixlen = dprefixlen;
                                    acl_rule_info->rule_id = 0; // here should be 0
                                    acl_rule_info->direction = FC_TOPO_DIRECTION_NONE;
                                    acl_rule_info->acl_group_index = item->acl_group_index;
                                    acl_rule_info_key = fnv1a_hash(acl_rule_info, sizeof(acl_rule_info));
                                    acl_rule_info->rule_id = rule_id; // fill it
                                    acl_rule_info->direction = FC_TOPO_DIRECTION_IN;
                                    HASH_ADD_INT(item->ht_acl_rule_info, acl_rule_info_key, acl_rule_info);

                                    //! offpath update acl-in direction
                                    rule_id = ++item->acl_rule_out_id;
                                    DIAG_INFO("offpath update acl-out direction, "
                                              "[%s:%d] group index: %u, "
                                              "ipversion: %d rule_id: %u, "
                                              "src prefix: %s/%d, dst prefix: %s/%d, "
                                              "iface_index: %08X\n",
                                              __FUNCTION__, __LINE__, item->acl_group_index,
                                              bm->ipversion, rule_id,
                                              saddr, sprefixlen, daddr, dprefixlen,
                                              iface_info->iface_index);
                                    py_apply_acl(&router_info->py_config,
                                                 item->acl_group_index,
                                                 bm->ipversion,
                                                 is_withdraw, rule_id,
                                                 saddr, sprefixlen,
                                                 daddr, dprefixlen,
                                                 iface_info->iface_index,
                                                 FC_TOPO_DIRECTION_OUT);
                                    acl_rule_info =
                                        (ht_acl_rule_info_t *)
                                            calloc(1, sizeof(ht_acl_rule_info_t));
                                    acl_rule_info->ipversion = bm->ipversion;
                                    memcpy(acl_rule_info->saddr, saddr, INET6_ADDRSTRLEN);
                                    acl_rule_info->sprefixlen = sprefixlen;
                                    memcpy(acl_rule_info->daddr, daddr, INET6_ADDRSTRLEN);
                                    acl_rule_info->dprefixlen = dprefixlen;
                                    acl_rule_info->rule_id = 0; // here should be 0
                                    acl_rule_info->direction = FC_TOPO_DIRECTION_NONE;
                                    acl_rule_info->acl_group_index = item->acl_group_index;
                                    acl_rule_info_key = fnv1a_hash(acl_rule_info, sizeof(acl_rule_info));
                                    acl_rule_info->rule_id = rule_id; // fill it
                                    acl_rule_info->direction = FC_TOPO_DIRECTION_OUT;
                                    HASH_ADD_INT(item->ht_acl_rule_info, acl_rule_info_key, acl_rule_info);
                                }
                            }
                            else // onpath node
                            {
                                direction = FC_TOPO_DIRECTION_NONE;
                                const char *direction_str = "none";
                                if (is_from_bgpd)
                                {
                                    direction = FC_TOPO_DIRECTION_IN;
                                    direction_str = "in";
                                }
                                /*
                                else
                                {
                                    if (fc_index < bm->fc_num)
                                    {
                                        if (link_info->neighbor_asn ==
                                            bm->fclist[fc_index].nexthop_asn)
                                        {
                                            direction = FC_TOPO_DIRECTION_IN;
                                            direction_str = "in";
                                        }
                                        else if (link_info->neighbor_asn ==
                                                 bm->fclist[fc_index].previous_asn)
                                        {
                                            direction = FC_TOPO_DIRECTION_OUT;
                                            direction_str = "out";
                                        }
                                    }
                                    // this is for the other ifaces that do not link to nasn or pasn.
                                    else
                                    {
                                        direction = FC_TOPO_DIRECTION_BOTH;
                                        direction_str = "both";
                                    }
                                }*/
                                DIAG_INFO("onpath node srcip: %s/%d, dstip: %s/%d, "
                                          "iface_index: %08X, direction: %s\n",
                                          saddr, sprefixlen, daddr, dprefixlen,
                                          iface_info->iface_index, direction_str);
                                if (direction == FC_TOPO_DIRECTION_NONE)
                                {
                                    continue;
                                }
                                if (direction & FC_TOPO_DIRECTION_IN)
                                {
                                    if (is_withdraw) // withdraw/del
                                    {
                                        ht_acl_rule_info_t *acl_rule_info = NULL;
                                        ht_acl_rule_info_t *rule =
                                            (ht_acl_rule_info_t *)calloc(1, sizeof(ht_acl_rule_info_t));
                                        rule->ipversion = bm->ipversion;
                                        memcpy(rule->saddr, saddr, INET6_ADDRSTRLEN);
                                        rule->sprefixlen = sprefixlen;
                                        memcpy(rule->daddr, daddr, INET6_ADDRSTRLEN);
                                        rule->dprefixlen = dprefixlen;
                                        rule->rule_id = 0;
                                        rule->direction = FC_TOPO_DIRECTION_NONE;
                                        rule->acl_group_index = item->acl_group_index;
                                        acl_rule_info_key = fnv1a_hash(rule, sizeof(rule));
                                        HASH_FIND_INT(item->ht_acl_rule_info, &acl_rule_info_key, acl_rule_info);

                                        if (acl_rule_info)
                                        {
                                            DIAG_INFO("onpath withdraw acl-in direction, "
                                                      "[%s:%d] group index: %u, "
                                                      "ipversion: %d rule_id: %u, "
                                                      "src prefix: %s/%d, dst prefix: %s/%d, "
                                                      "iface_index: %08X\n",
                                                      __FUNCTION__, __LINE__, item->acl_group_index,
                                                      bm->ipversion, acl_rule_info->rule_id,
                                                      saddr, sprefixlen, daddr, dprefixlen,
                                                      iface_info->iface_index);
                                            py_apply_acl(&router_info->py_config,
                                                         item->acl_group_index,
                                                         bm->ipversion,
                                                         is_withdraw,
                                                         acl_rule_info->rule_id,
                                                         saddr, sprefixlen,
                                                         daddr, dprefixlen,
                                                         iface_info->iface_index,
                                                         FC_TOPO_DIRECTION_IN);
                                            HASH_DEL(item->ht_acl_rule_info, acl_rule_info);
                                            free(acl_rule_info);
                                        }
                                        else
                                        {
                                            DIAG_INFO("no such onpath withdraw acl-in direction, "
                                                      "[%s:%d] group index: %u, "
                                                      "ipversion: %d fake rule_id: %u, "
                                                      "src prefix: %s/%d, dst prefix: %s/%d, "
                                                      "iface_index: %08X\n",
                                                      __FUNCTION__, __LINE__, item->acl_group_index,
                                                      bm->ipversion, rule_id,
                                                      saddr, sprefixlen, daddr, dprefixlen,
                                                      iface_info->iface_index);
                                        }
                                        free(rule);
                                    }
                                    else
                                    {
                                        rule_id = ++item->acl_rule_in_id;
                                        DIAG_INFO("onpath update acl-in direction, "
                                                  "[%s:%d] group index: %u, "
                                                  "ipversion: %d rule_id: %u, "
                                                  "src prefix: %s/%d, dst prefix: %s/%d, "
                                                  "iface_index: %08X\n",
                                                  __FUNCTION__, __LINE__, item->acl_group_index,
                                                  bm->ipversion, rule_id,
                                                  saddr, sprefixlen, daddr, dprefixlen,
                                                  iface_info->iface_index);
                                        py_apply_acl(&router_info->py_config,
                                                     item->acl_group_index,
                                                     bm->ipversion,
                                                     is_withdraw,
                                                     rule_id,
                                                     saddr, sprefixlen,
                                                     daddr, dprefixlen,
                                                     iface_info->iface_index,
                                                     FC_TOPO_DIRECTION_IN);
                                        ht_acl_rule_info_t *acl_rule_info =
                                            (ht_acl_rule_info_t *)calloc(1, sizeof(ht_acl_rule_info_t));
                                        acl_rule_info->ipversion = bm->ipversion;
                                        memcpy(acl_rule_info->saddr, saddr, INET6_ADDRSTRLEN);
                                        acl_rule_info->sprefixlen = sprefixlen;
                                        memcpy(acl_rule_info->daddr, daddr, INET6_ADDRSTRLEN);
                                        acl_rule_info->dprefixlen = dprefixlen;
                                        acl_rule_info->rule_id = 0;
                                        acl_rule_info->direction = FC_TOPO_DIRECTION_NONE;
                                        acl_rule_info->acl_group_index = item->acl_group_index;
                                        acl_rule_info_key = fnv1a_hash(acl_rule_info, sizeof(acl_rule_info));
                                        acl_rule_info->rule_id = rule_id;
                                        acl_rule_info->direction = FC_TOPO_DIRECTION_IN;
                                        HASH_ADD_INT(item->ht_acl_rule_info, acl_rule_info_key, acl_rule_info);
                                    }
                                }
                                if (direction & FC_TOPO_DIRECTION_OUT)
                                {
                                    if (is_withdraw)
                                    {
                                        ht_acl_rule_info_t *acl_rule_info = NULL;
                                        ht_acl_rule_info_t *rule =
                                            (ht_acl_rule_info_t *)calloc(1, sizeof(ht_acl_rule_info_t));
                                        rule->ipversion = bm->ipversion;
                                        memcpy(rule->saddr, saddr, INET6_ADDRSTRLEN);
                                        rule->sprefixlen = sprefixlen;
                                        memcpy(rule->daddr, daddr, INET6_ADDRSTRLEN);
                                        rule->dprefixlen = dprefixlen;
                                        rule->rule_id = 0;
                                        rule->direction = FC_TOPO_DIRECTION_NONE;
                                        rule->acl_group_index = item->acl_group_index;
                                        acl_rule_info_key = fnv1a_hash(rule, sizeof(rule));
                                        HASH_FIND_INT(item->ht_acl_rule_info, &acl_rule_info_key, acl_rule_info);

                                        if (acl_rule_info)
                                        {
                                            DIAG_INFO("onpath withdraw acl-in direction, "
                                                      "[%s:%d] group index: %u, "
                                                      "ipversion: %d rule_id: %u, "
                                                      "src prefix: %s/%d, dst prefix: %s/%d, "
                                                      "iface_index: %08X\n",
                                                      __FUNCTION__, __LINE__, item->acl_group_index,
                                                      bm->ipversion, acl_rule_info->rule_id,
                                                      saddr, sprefixlen, daddr, dprefixlen,
                                                      iface_info->iface_index);
                                            py_apply_acl(&router_info->py_config,
                                                         item->acl_group_index,
                                                         bm->ipversion,
                                                         is_withdraw,
                                                         acl_rule_info->rule_id,
                                                         saddr, sprefixlen,
                                                         daddr, dprefixlen,
                                                         iface_info->iface_index,
                                                         FC_TOPO_DIRECTION_OUT);
                                            HASH_DEL(item->ht_acl_rule_info, acl_rule_info);
                                            free(acl_rule_info);
                                        }
                                        else
                                        {
                                            DIAG_INFO("no such onpath withdraw acl-in direction, "
                                                      "[%s:%d] group index: %u, "
                                                      "ipversion: %d fake rule_id: %u, "
                                                      "src prefix: %s/%d, dst prefix: %s/%d, "
                                                      "iface_index: %08X\n",
                                                      __FUNCTION__, __LINE__, item->acl_group_index,
                                                      bm->ipversion, rule_id,
                                                      saddr, sprefixlen, daddr, dprefixlen,
                                                      iface_info->iface_index);
                                        }
                                        free(rule);
                                    }
                                    else
                                    {
                                        rule_id = ++item->acl_rule_out_id;
                                        DIAG_INFO("onpath update acl-out direction, "
                                                  "[%s:%d] group index: %u, "
                                                  "ipversion: %d rule_id: %u, "
                                                  "src prefix: %s/%d, dst prefix: %s/%d, "
                                                  "iface_index: %08X\n",
                                                  __FUNCTION__, __LINE__, item->acl_group_index,
                                                  bm->ipversion, rule_id,
                                                  saddr, sprefixlen, daddr, dprefixlen,
                                                  iface_info->iface_index);
                                        py_apply_acl(&router_info->py_config,
                                                     item->acl_group_index,
                                                     bm->ipversion,
                                                     is_withdraw,
                                                     rule_id,
                                                     saddr, sprefixlen,
                                                     daddr, dprefixlen,
                                                     iface_info->iface_index,
                                                     FC_TOPO_DIRECTION_OUT);
                                        ht_acl_rule_info_t *acl_rule_info =
                                            (ht_acl_rule_info_t *)calloc(1, sizeof(ht_acl_rule_info_t));
                                        acl_rule_info->ipversion = bm->ipversion;
                                        memcpy(acl_rule_info->saddr, saddr, INET6_ADDRSTRLEN);
                                        acl_rule_info->sprefixlen = sprefixlen;
                                        memcpy(acl_rule_info->daddr, daddr, INET6_ADDRSTRLEN);
                                        acl_rule_info->dprefixlen = dprefixlen;
                                        acl_rule_info->rule_id = 0;
                                        acl_rule_info->direction = FC_TOPO_DIRECTION_NONE;
                                        acl_rule_info->acl_group_index = item->acl_group_index;
                                        acl_rule_info_key = fnv1a_hash(acl_rule_info, sizeof(acl_rule_info));
                                        acl_rule_info->rule_id = rule_id;
                                        acl_rule_info->direction = FC_TOPO_DIRECTION_OUT;
                                        HASH_ADD_INT(item->ht_acl_rule_info, acl_rule_info_key, acl_rule_info);
                                    }
                                }
                            }
                        }
                        link_info = link_info->next;
                    }
                    router_info = router_info->next;
                }
            }
        }

        return ret;
    }

    int fc_acl_gen(int clisockfd, const FC_msg_bm_t *bm)
    {
        DIAG_INFO("### Gen ACL START ###\n");

        switch (g_fc_server.use_data_plane)
        {
        case FC_DP_MODE_LINUX:
            fc_acl_gen_linux(clisockfd, bm);
            break;
        case FC_DP_MODE_H3C:
            fc_acl_gen_h3c(clisockfd, bm);
            break;
        case FC_DP_MODE_NONE:
            break;
        default:
            DIAG_ERROR("ERROR: NOT SUPPORTED DP MODE: %d\n",
                       g_fc_server.use_data_plane);
            break;
        }

        DIAG_INFO("### Gen ACL ENDED ###\n");

        return 0;
    }

#ifdef __cplusplus
}
#endif /* __cplusplus */
