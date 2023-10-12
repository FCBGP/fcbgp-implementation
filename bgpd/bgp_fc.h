/******************************************************
 * File Name:    bgp_fc.h
 * Author:       basilguo@163.com
 * Created Time: 2023-09-19 02:21:30
 * Description:
 ******************************************************/
#ifndef BGP_FC_H
#define BGP_FC_H

#include "bgp_config.h"

#define MAX_FC 256
#define FCS_SIZE (sizeof(FC_t) * MAX_FC)

typedef struct FC_s
{
    u32 previous_asn;
    u32 current_asn;
    u32 nexthop_asn;
    u8 ski[20];
    u8 algo_id;
    u8 flags;
    u16 siglen;
    u8 sig[80]; // DER format default 64B => ~72B
} FC_t;

typedef struct FCList_s
{
    int length; // length of FCs
    int size; // number of FC in fcs
//    u8 fcs[FCS_SIZE];
    FC_t fcs[MAX_FC];  //FC_t *fcs;
} FCList_t;

#endif // BGP_FC_H

