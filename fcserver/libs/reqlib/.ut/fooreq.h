#ifndef _FOOREQ_H_
#define _FOOREQ_H_

#include "libreq.h"

extern req_ctx_t *g_foo_req;
extern int foo_req_init(void);
extern void foo_req_fini(void);
extern int foo_add_req(req_ctx_t *req, int num, char *str);
extern int foo_del_req(req_ctx_t *req, int num, char *str);
extern int foo_tty_req(req_ctx_t *req, char *str);

#endif
