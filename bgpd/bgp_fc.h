/******************************************************
 * File Name:    bgp_fc.h
 * Author:       basilguo@163.com
 * Created Time: 2023-09-19 02:21:30
 * Description:
 ******************************************************/
#ifndef BGP_FC_H
#define BGP_FC_H

#include <stdint.h>

typedef u8 uint8_t;
typedef u16 uint16_t;
typedef u32 uint32_t;
typedef u64 uint64_t;

typedef struct FC_s
{
    u32 cur_as;
    u32 next_hop;
    u8 ski[20];
    u8 algo_id;
    u8 flags;
    u16 length;
    u8[72] signature;
} FC_t;

typedef struct FCList_s
{
    int size; // number of FC in fcs
    int length; // length of FCs
    FC_t *fcs;
} FCList_t;

#endif // BGP_FC_H

