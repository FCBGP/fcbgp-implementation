/********************************************************************************
* File Name:    json_utils.h
* Author:       basilguo@163.com
* Created Time: 2023-09-27 09:27:53
* Description:
********************************************************************************/

#ifndef JSON_UTILS_H
#define JSON_UTILS_H

#include "utils.h"
#include "mln_hash.h"

extern int read_asn_ips(const char *fname, fcserver_t *fcserver,
        mln_hash_t *h, int *asns, int *asns_size);

#endif // JSON_UTILS_H
