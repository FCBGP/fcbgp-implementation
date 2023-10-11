/********************************************************************************
* File Name:    common.h
* Author:       basilguo@163.com
* Created Time: 2023-09-27 08:20:43
* Description:
********************************************************************************/

#ifndef COMMON_H
#define COMMON_H

#include <stdbool.h>
#include <stdint.h>

typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

#define IPV4                            4
#define IPV6                            6

#define IP4_LENGTH                      4
#define IP6_LENGTH                     16

#define HDR_GENERAL_LENGTH              4

#define BUFF_SIZE 2048
#define FCSRV_MAX_LINK_AS 256
#define FCSRV_MAX_SRC_PREFIX 256

#define TCP_PROTO 0x06

#define SKI_LENGTH 20

#define MSG_SKI                         1
#define MSG_BGPD                        2
#define MSG_BC                          3



#endif // COMMON_H
