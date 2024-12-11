/******************************************************
 * File Name:    bgp_fc.h
 * Author:       basilguo@163.com
 * Created Time: 2023-09-19 02:21:30
 * Description:
 ******************************************************/
#ifndef BGP_FC_H
#define BGP_FC_H

#include <getopt.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "defines.h"

#define FC_PROGRAM_NAME "fcserver"
#define FC_EPOLL_MAX_EVENTS 32
#define FC_SOCK_BACKLOG 32

#define FC_BM_PATH_NODE_TYPE_ONPATH 0x00
#define FC_BM_PATH_NODE_TYPE_OFFPATH 0x80
#define FC_BM_UPDATE_TYPE_ADD 0x00
#define FC_BM_UPDATE_TYPE_DEL 0x40

typedef enum
{
    FC_TOPO_DIRECTION_NONE = 0x00,
    FC_TOPO_DIRECTION_IN = 0x01,
    FC_TOPO_DIRECTION_OUT = 0x02,
    FC_TOPO_DIRECTION_BOTH = 0x03,
} direction_e;

extern void* fc_server_main_backend(void* args);
extern int fc_server_create(void);
extern void fc_server_destroy(int signum);
extern int fc_server_handler(int clisockfd, char* buff, int buffsize,
                             int recvlen);
extern int fc_server_pubkey_handler(int clisockfd, const unsigned char* buff,
                                    int bufflen);
extern int fc_server_bm_handler(int clisockfd, unsigned char* buff, int bufflen,
                                int msg_type);
extern int fc_server_topo_handler(int clisockfd, const unsigned char* buff,
                                  int bufflen);
extern int fc_server_topo_del_all_routers(void);
extern int fc_sock_get_addr_from_peer_fd(int fd, struct sockaddr* sockaddr,
                                         char* ipbuf, int buffsize);

extern bool fc_asn_is_offpath(u32 asn, const FC_msg_bm_t* bm);
extern int fc_acl_gen(int clisockfd, const FC_msg_bm_t* bm);
extern int fc_bm_find_server(uint32_t asn, char* ifaddr, char* ifname);
extern int fc_server_topo_init_msg(int clisockfd);

extern void* fc_main_front(void* args);

extern void fc_cmd_help(void);
extern void fc_cmd_acl(void);
extern void fc_cmd_bm(void);
extern void fc_cmd_info(void);
extern void fc_cmd_link(void);
extern void fc_cmd_version(void);
extern void fc_cmd_quit(void);
extern void fc_cmd_help(void);

#endif // BGP_FC_H
