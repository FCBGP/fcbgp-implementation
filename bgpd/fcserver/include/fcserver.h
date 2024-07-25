/******************************************************
 * File Name:    bgp_fc.h
 * Author:       basilguo@163.com
 * Created Time: 2023-09-19 02:21:30
 * Description:
 ******************************************************/
#ifndef BGP_FC_H
#define BGP_FC_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <getopt.h>

#include <arpa/inet.h>
#include <netdb.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <signal.h>
#include <time.h>
#include <pthread.h>
#include <unistd.h>

#include "libncs6.h"
#include "defines.h"

#define FC_PROGRAM_NAME "fcserver"
#define FC_EPOLL_MAX_EVENTS 32
#define FC_SOCK_BACKLOG 32

extern int fc_main();
extern int fc_server_create(void);
extern void fc_server_destroy(int signum);
extern int fc_server_handler(int clisockfd, char *buff, int buffsize, int recvlen);
extern int fc_server_pubkey_handler(int clisockfd, const char *buff, int bufflen);
extern int fc_server_bm_handler(int clisockfd, char *buff, int bufflen, int msg_type);
extern int fc_server_topo_handler(int clisockfd, const char *buff, int bufflen);

#endif // BGP_FC_H

