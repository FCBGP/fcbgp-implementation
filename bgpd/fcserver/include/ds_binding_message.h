/********************************************************************************
* File Name:    ds_binding_message.h
* Author:       basilguo@163.com
* Created Time: 2023-09-28 06:00:16
* Description:
********************************************************************************/

#ifndef DS_BINDING_MESSAGE_H
#define DS_BINDING_MESSAGE_H

#include "common.h"
#include "ds_asn_ip.h"
#include "bgp_fc.h"

typedef struct fcmsg_hdr_st
{
    u8 type; // 1 for pubkey, 2 for bm
    u16 length;
    u8 reserved;
} __attribute__((packed)) fcmsg_hdr_t;

typedef struct fcmsg_bm_st
{
    u8 ipversion;       // 1 for ipv4, 2 for ipv6
    u8 type;            // 0 for onpath nodes, 1 for offpath
    u8 action;          // 0 for add/update, 1 for del/withdraw
    u8 fc_num;          // num of fc in fclist, boundary
    u8 src_ip_num;      // src ip prefix num, boundary
    u8 dst_ip_num;      // dst ip prefix num, boundary
    u16 siglen;
    u32 local_asn;      // local as number
    u32 version;
    u32 subversion;
    ip_t src_ip[FCSRV_MAX_SRC_PREFIX];
    ip_t dst_ip[FCSRV_MAX_SRC_PREFIX];
    FC_t fclist[FCSRV_MAX_LINK_AS];
    u8 ski[20];
    u8 signature[80];
} __attribute__((packed)) fcmsg_bm_t;

typedef struct fcmsg_bm_new_s
{
    fcmsg_bm_t old_bm;
    u8 new_fc_num;
    u8 new_as_num;
    FC_t new_fclist[FCSRV_MAX_LINK_AS];
    u8 new_ski[20];
    u8 new_signature[80];
} __attribute__((packed)) fcmsg_bm_new_t;

#endif // ds_binding_message_h

