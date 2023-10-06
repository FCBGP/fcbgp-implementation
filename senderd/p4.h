#ifndef _P4_H__
#define _P4_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "ip6.h"
#include "cJSON.h"
#include "libcache.h"
#include "libmbs.h"
#include "libdiag.h"
#include "hex.h"

#define CONFIG_FILE "./p4.json"

extern uint8_t g_scanner_smac[6];
extern uint8_t g_scanner_dmac[6];
extern uint8_t g_scanner_sip6[64];
extern uint8_t g_scanner_dip6[64];

extern cJSON *g_cJSON_start;
extern cJSON *g_cJSON_eth;
extern cJSON *g_cJSON_ipv6;
extern cJSON *g_cJSON_udp;
extern cJSON *g_cJSON_p4;
extern char *g_payload;

extern int gen_p4_pkt(char *ifname, unsigned char *p4_pkt, unsigned int *p4_len);
extern int reverse_uint32(uint32_t *src);
extern uint32_t get_key_by_indi(uint32_t indi);
extern int get_keystr_by_indi(uint32_t indi, unsigned char *res);
extern int print_pkt(unsigned char *start, unsigned char *end);

#endif
