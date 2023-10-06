#ifndef _LIB_REQAPI_H_
#define _LIB_REQAPI_H_

#include "libreq.h"

typedef struct sender_meta_st {
    char *file;
    char *ipver;
    char *srcip;
    char *dstip;
    char *proto;
    uint64_t count;
    uint64_t interval;

} sender_meta_t;

#define sender_meta_set_file(meta, str) do {mbsfree((meta)->file);(meta)->file=mbsnew(str);} while (0)
#define sender_meta_set_ipver(meta, str) do {mbsfree((meta)->ipver);(meta)->ipver=mbsnew(str);} while (0)
#define sender_meta_set_srcip(meta, str) do {mbsfree((meta)->srcip);(meta)->srcip=mbsnew(str);} while (0)
#define sender_meta_set_dstip(meta, str) do {mbsfree((meta)->dstip);(meta)->dstip=mbsnew(str);} while (0)
#define sender_meta_set_proto(meta, str) do {mbsfree((meta)->proto);(meta)->proto=mbsnew(str);} while (0)
#define sender_meta_set_count(meta, u32) do {(meta)->count=u32;} while (0)
#define sender_meta_set_interval(meta, u32) do {(meta)->interval=u32;} while (0)

/* senderdreq.c */
extern req_ctx_t *g_sender_req;
extern int sender_req_init(void);
extern void sender_req_fini(void);
extern int sender_version_req(req_ctx_t *req);

#if 0
extern int user_add_req(req_ctx_t * req, char *nid, char *stuno, char *name, char *idcode, int sex, char *tel, \
        char *phone, char *email, char *address, int onlinemax, char *passwd);
#endif
#endif
