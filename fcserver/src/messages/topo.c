/**
 * @file topo.c
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
#include <stdio.h>
#include <stdlib.h>

    int fc_server_topo_init_msg(int clisockfd)
    {
        FC_msg_bm_t* pbm = NULL;
        int i = 0, bmnum = 0;

        pbm = fc_db_read_bms(&bmnum);

        for (i = 0; i < bmnum; ++i)
        {
            fc_acl_gen(clisockfd, &pbm[i]);
        }

        free(pbm);

        return 0;
    }

    static int
    fc_server_topo_find_iface(FC_router_link_info_t* link_info, u32 iface_index,
                              FC_router_iface_info_t** iface_info,
                              FC_router_iface_info_t** prev_iface_info)
    {
        *iface_info = *prev_iface_info = link_info->iface_list;
        while (*iface_info)
        {
            if ((*iface_info)->iface_index == iface_index)
            {
                break;
            }
            *prev_iface_info = *iface_info;
            *iface_info = (*iface_info)->next;
        }

        return 0;
    }

    static int
    fc_server_topo_find_router(FC_router_info_t* target_router,
                               u32 neighbor_asn,
                               FC_router_link_info_t** link_info,
                               FC_router_link_info_t** prev_link_info)
    {
        *prev_link_info = *link_info = target_router->links;
        while (*link_info)
        {
            if ((*link_info)->neighbor_asn == neighbor_asn)
            {
                break;
            }
            *prev_link_info = *link_info;
            *link_info = (*link_info)->next;
        }

        return 0;
    }

    static int fc_server_topo_del_one_link(FC_router_link_info_t* link_info,
                                           u32 iface_index)
    {
        FC_router_iface_info_t *prev_iface_info = NULL, *iface_info = NULL;

        fc_server_topo_find_iface(link_info, iface_index, &iface_info,
                                  &prev_iface_info);

        if (iface_info)
        {
            if (prev_iface_info != iface_info)
            {
                prev_iface_info->next = iface_info->next;
            }
            else
            {
                link_info->iface_list = iface_info->next;
            }
            free(iface_info);
        }

        return 0;
    }

    static int fc_server_topo_del_one_neighbor(FC_router_link_info_t* link_info)
    {
        FC_router_iface_info_t *iface_info = NULL, *next_iface_info = NULL;

        iface_info = link_info->iface_list;
        while (iface_info)
        {
            next_iface_info = iface_info->next;
            free(iface_info);
            iface_info = next_iface_info;
        }
        free(link_info);

        return 0;
    }

    static int fc_server_topo_del_all_neighbors(FC_router_info_t* target_router)
    {
        FC_router_link_info_t *link_info = NULL, *next_link_info = NULL;

        link_info = target_router->links;
        while (link_info)
        {
            next_link_info = link_info->next;
            fc_server_topo_del_one_neighbor(link_info);
            link_info = next_link_info;
        }
        target_router->links = NULL;

        return 0;
    }

    /* used when destroying the fcs. */
    int fc_server_topo_del_all_routers(void)
    {
        FC_router_info_t *router_info = NULL, *next_router_info = NULL;

        router_info = g_fc_server.routers;
        while (router_info)
        {
            next_router_info = router_info->next;
            fc_server_topo_del_all_neighbors(router_info);
            close(router_info->fd);
            free(router_info);
            router_info = next_router_info;
        }
        g_fc_server.routers = NULL;

        return 0;
    }

    static int fc_server_topo_del(FC_router_info_t* target_router,
                                  u32 neighbor_num, const unsigned char* buff,
                                  int currlen)
    {
        int i = 0, k = 0;
        u32 neighbor_asn = 0, il_num = 0, iface_index = 0;
        u32* iface_list = NULL;
        FC_router_link_info_t *link_info = NULL, *prev_link_info = NULL;

        // delete all neighbors of this bgp router
        if (neighbor_num == 0xFFFFFFFF)
        {
            fc_server_topo_del_all_neighbors(target_router);
            return currlen;
        }

        iface_list = (u32*)malloc(sizeof(u32) * il_num);
        FC_ASSERT_RETP(iface_list);

        // delete part neighbors of this bgp router
        for (i = 0; i < neighbor_num; ++i)
        {
            // neighbor-asn
            memcpy(&neighbor_asn, buff + currlen, sizeof(u32));
            neighbor_asn = ntohl(neighbor_asn);
            currlen += sizeof(u32);
            // il-num
            memcpy(&il_num, buff + currlen, sizeof(u32));
            il_num = ntohl(il_num);
            currlen += sizeof(u32);
            // iface-list
            if (il_num != 0xFFFFFFFF)
            {
                memcpy(iface_list, buff + currlen, sizeof(u32) * il_num);
                currlen += sizeof(u32) * il_num;
            }

            // find the neighbor
            prev_link_info = link_info = target_router->links;
            fc_server_topo_find_router(target_router, neighbor_asn, &link_info,
                                       &prev_link_info);
            if (link_info == NULL)
            {
                // no such neighbor
                continue;
            }

            if (il_num == 0xFFFFFFFF || il_num == 0)
            {
                if (prev_link_info)
                {
                    prev_link_info->next = link_info->next;
                }
                else
                {
                    target_router->links = link_info->next;
                }
                fc_server_topo_del_one_neighbor(link_info);
            }
            else
            {
                for (k = 0; k < il_num; ++k)
                {
                    // iface
                    iface_index = ntohl(iface_list[k]);
                    fc_server_topo_del_one_link(link_info, iface_index);
                }
            }
        }

        free(iface_list);

        return currlen;
    }

    static int fc_server_topo_add(FC_router_info_t* target_router,
                                  u32 neighbor_num, const unsigned char* buff,
                                  int currlen)
    {
        int j = 0, k = 0, ret = 0;
        u32 neighbor_asn = 0, il_num = 0, iface_index = 0;
        FC_router_link_info_t *link_info = NULL, *prev_link_info = NULL;
        FC_router_iface_info_t *iface_info = NULL, *prev_iface_info = NULL;

        // remove all neighbor infos as h3c uses full update policy.
        fc_server_topo_del_all_neighbors(target_router);

        for (j = 0; j < neighbor_num; ++j)
        {
            // neighbor-asn
            memcpy(&neighbor_asn, buff + currlen, sizeof(u32));
            neighbor_asn = ntohl(neighbor_asn);
            currlen += sizeof(u32);
            // il-num
            memcpy(&il_num, buff + currlen, sizeof(u32));
            il_num = ntohl(il_num);
            currlen += sizeof(u32);
            if (il_num == 0)
            {
                continue;
            }

            // find the neighbor
            prev_link_info = link_info = target_router->links;
            fc_server_topo_find_router(target_router, neighbor_asn, &link_info,
                                       &prev_link_info);

            if (link_info == NULL)
            {
                // no such neighbor
                link_info = calloc(1, sizeof(FC_router_link_info_t));
                FC_ASSERT_RETP(link_info);
                if (prev_link_info)
                {
                    prev_link_info->next = link_info;
                }
                else
                {
                    target_router->links = link_info;
                }
            }
            link_info->neighbor_asn = neighbor_asn;

            // iface-list
            for (k = 0; k < il_num; ++k)
            {
                memcpy(&iface_index, buff + currlen, sizeof(u32));
                iface_index = ntohl(iface_index);
                currlen += sizeof(u32);
                fc_server_topo_find_iface(link_info, iface_index, &iface_info,
                                          &prev_iface_info);
                if (iface_info == NULL)
                {
                    // no such iface
                    iface_info = (FC_router_iface_info_t*)calloc(
                        1, sizeof(FC_router_iface_info_t));
                    FC_ASSERT_RETP(iface_info);
                    if (prev_iface_info)
                    {
                        prev_iface_info->next = iface_info;
                    }
                    else
                    {
                        link_info->iface_list = iface_info;
                    }
                }
                iface_info->iface_index = iface_index;
                // insert into ht
                ret = ht_aclinfo_insert(g_fc_server.ht_acl_group_info,
                                        iface_index, target_router);
                FC_ASSERT_RET(ret);
            }
        }

        return currlen;
    }

    static int fc_server_topo_print(FC_router_info_t* target_router)
    {
        DIAG_INFO("bgpid: %d.%d.%d.%d\n", (target_router->bgpid >> 24) % 256,
                  (target_router->bgpid >> 16) % 256,
                  (target_router->bgpid >> 8) % 256,
                  target_router->bgpid % 256);
        for (FC_router_link_info_t* link_info = target_router->links;
             link_info != NULL; link_info = link_info->next)
        {
            DIAG_INFO("  neighbor asn: %d\n", link_info->neighbor_asn);
            FC_router_iface_info_t* iface_info = link_info->iface_list;
            while (iface_info)
            {
                DIAG_INFO("    iface: %d\n", iface_info->iface_index);
                iface_info = iface_info->next;
            }
        }

        return 0;
    }

    int fc_server_topo_handler(int clisockfd, const unsigned char* buff,
                               int len)
    {
        DIAG_INFO("### TOPO LINK INFO START ###\n");

        int i = 0, currlen = 0, ret = 0;
        u8 action = 0, reserved = 0;
        u32 bgpid = 0, local_asn = 0, neighbor_num = 0;
        FC_router_info_t* target_router = NULL;

        currlen = FC_HDR_GENERAL_LENGTH;

        // action
        memcpy(&action, buff + currlen, sizeof(u8));
        currlen += sizeof(u8);
        // reserved
        for (i = 0; i < 3; ++i)
        {
            memcpy(&reserved, buff + currlen, sizeof(u8));
            currlen += sizeof(u8);
        }
        // bgpid
        memcpy(&bgpid, buff + currlen, sizeof(u32));
        bgpid = ntohl(bgpid);
        currlen += sizeof(u32);
        // local-asn
        memcpy(&local_asn, buff + currlen, sizeof(u32));
        local_asn = ntohl(local_asn);
        currlen += sizeof(u32);
        // neighbor-num
        memcpy(&neighbor_num, buff + currlen, sizeof(u32));
        neighbor_num = ntohl(neighbor_num);
        currlen += sizeof(u32);

        if (local_asn != g_fc_server.local_asn)
        {
            DIAG_ERROR("ERROR: topo link info, bgpid: %08X belongs to asn: %d, "
                       "but not belongs to local asn: %d\n",
                       bgpid, local_asn, g_fc_server.local_asn);
            return -1;
        }
        // g_fc_server.routers should be prepared in reading config
        for (target_router = g_fc_server.routers; target_router != NULL;
             target_router = target_router->next)
        {
            if (target_router->bgpid == bgpid)
            {
                break;
            }
        }

        if (target_router == NULL)
        {
            DIAG_ERROR("ERROR: Cannot find the bgp router, bgpid: %08X\n",
                       bgpid);
            // fc_server_destroy(SIGUSR1);
            return -1;
        }

        // fd
        if (target_router->fd != 0 && target_router->fd != clisockfd)
        {
            // TODO del all neighbors
            // TODO close the target-link fd
        }
        target_router->fd = clisockfd;

        switch (action)
        {
            case FC_ACT_ADD:
                currlen = fc_server_topo_add(target_router, neighbor_num, buff,
                                             currlen);
                break;
            case FC_ACT_DEL:
                // TODO
                currlen = fc_server_topo_del(target_router, neighbor_num, buff,
                                             currlen);
                break;
            default:
                DIAG_ERROR("ERROR: Unkown action: %d for neighbor links\n",
                           action);
                break;
        }

        fc_server_topo_print(target_router);

        DIAG_INFO("### TOPO LINK INFO ENDED ###\n");

        return ret;
    }

#ifdef __cplusplus
}
#endif /* __cplusplus */
