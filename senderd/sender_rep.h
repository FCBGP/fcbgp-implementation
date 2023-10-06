#ifndef _GEN_ADDRREP_H_
#define _GEN_ADDRREP_H_

#include "librep.h"

typedef struct SRV_PKT_FMT_s
{
    uint8_t ip_version; // 4 for ipv4, 6 for ipv6
    uint8_t prefix_length; // 0-128
    uint8_t src_prelen; // 0-128
    uint8_t dst_prelen; // 0-128
    uint8_t rule_type; // 0 for acl, 1 for route
    uint8_t port_type; // 0 for portid
    uint8_t protocol; // 0 for all
    uint8_t reserved; // 0
    union {
        uint32_t ip4;
        uint32_t ip6[4];
    } src_ip;
    union {
        uint32_t ip4;
        uint32_t ip6[4];
    } dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t  port;
} __attribute__((aligned)) SRV_PKT_FMT_t;

/* senderrep.c */
extern rep_ctx_t *g_sender_rep;
extern int sender_rep_init(void);
extern int sender_rep_register(dispatch_command_t *commands);
extern int sender_rep_start(void);
extern void sender_rep_loop(void);
extern void sender_rep_fini(void);

extern int ncs_sender_init();

extern int sender_version_rep(rep_worker_t *worker);

extern dispatch_command_t g_sender_commands[];
#endif
