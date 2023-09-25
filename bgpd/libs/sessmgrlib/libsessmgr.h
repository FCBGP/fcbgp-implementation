#ifndef _LIBSESSMGR_H_
#define _LIBSESSMGR_H_ 1

#include "liblist.h"
#include "libmutex.h"
#include "libstring.h"
#include "libmsgpack.h"

enum {
    SESS_TYPE_CLI = 0,
    SESS_TYPE_WEBUI,

    SESS_TYPE_MAX
};

typedef struct sess_node_st {
    struct list_head node;

    int sessid;
    int timeout;
    int expired;

    uint16_t type;
    uint16_t sport;

    char token[33];
    char sipaddr[33];
    char username[33];
} sess_node_t;

static inline int sess_node_timeout(sess_node_t *node)
{
    if (node->expired <= time(NULL)) {
        return 1;
    }

    return 0;
}

static inline int sess_node_pack(mpack_ctx_t *encoder, sess_node_t *node, int flag)
{
    if (flag) {
        mpack_write_map(encoder, 8);
    } else {
        mpack_write_map(encoder, 7);
    }

    mpack_write_str(encoder, "id", 2);
    mpack_write_int(encoder, node->sessid);
    mpack_write_str(encoder, "timeout", 7);
    mpack_write_int(encoder, node->timeout);
    mpack_write_str(encoder, "expired", 7);
    mpack_write_int(encoder, node->expired);
    mpack_write_str(encoder, "type", 4);
    mpack_write_int(encoder, node->type);
    mpack_write_str(encoder, "sport", 5);
    mpack_write_u16(encoder, node->sport);
    if (flag) {
        mpack_write_str(encoder, "token", 5);
        mpack_write_str(encoder, node->token, strlen(node->token));
    }
    mpack_write_str(encoder, "sipaddr", 7);
    mpack_write_str(encoder, node->sipaddr, strlen(node->sipaddr));
    mpack_write_str(encoder, "username", 8);
    mpack_write_str(encoder, node->username, strlen(node->username));

    return 0;
}

typedef struct sess_ctx_st {
    struct list_head head;
    mutex_t mutex;
    int sessidx;
    int sesscnt;
} sess_ctx_t;

extern int sess_mgr_init(void);
extern void sess_mgr_clear(void);
extern void sess_mgr_fini(void);
extern int sess_mgr_insert(mpack_ctx_t *encoder, char *username, char *sipaddr, uint16_t sport, int timeout, int type);
extern int sess_mgr_delete(int sessid);
extern int sess_mgr_refresh(char *username, int type);
extern int sess_mgr_timeout(void);
extern int sess_mgr_list(mpack_ctx_t *encoder);
extern int sess_mgr_find_user(mpack_ctx_t *encoder, char *username, int type);
extern int sess_mgr_find_token(mpack_ctx_t *encoder, char *token);

#endif

