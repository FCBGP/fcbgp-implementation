#include "libreq.h"
#include "libdiag.h"
#include "libapi.h"

req_ctx_t *g_web_req = NULL;

int web_req_init(void)
{
    g_web_req = req_create("webreq", WEBD_ADDRESS);
    if (g_web_req == NULL) {
        DIAG_ERROR("create web req failed.\n");
        return -ENOMEM;
    }

    return 0;
}

void web_req_fini(void)
{
    req_destroy(g_web_req);
}

int web_add_va_req(req_ctx_t *req, int state, int level, char *fmt, va_list ap)
{
    int len = 0;
    char msg[256] = {0, };
    char *command = WEB_COMMAND_EVENT_SEND;

    if (req == NULL) {
        return -EINVAL;
    }

    len = vsnprintf(msg, sizeof(msg), fmt, ap);

    mpack_write_str(&req->encoder, command, strlen(command));
    mpack_write_int(&req->encoder, state);
    mpack_write_int(&req->encoder, level);
    mpack_write_str(&req->encoder, msg, len);

    return req_request(req);
}

int web_event_req(req_ctx_t *req, int state, int level, char *fmt, ...)
{
    int ret;
    va_list ap;

    if (req == NULL) {
        return -EINVAL;
    }

    va_start(ap, fmt);
    ret = web_add_va_req(req, state, level, fmt, ap);
    va_end(ap);

    return ret;
}

int web_config_show_req(req_ctx_t * req)
{
    char * command = WEB_COMMAND_CONFIG_SHOW;

    if (req == NULL) {
        return -EINVAL;
    }

    mpack_write_str(&req->encoder, command, strlen(command));

    return req_request(req);
}

int web_config_reset_req(req_ctx_t * req, int nidlen, int fenjie, int zuzhi, int yonghu, char *ippre)
{
    char * command = WEB_COMMAND_CONFIG_RESET;
    if (req == NULL) {
        return -EINVAL;
    }

    mpack_write_str(&req->encoder, command, strlen(command));
    mpack_write_int(&req->encoder, nidlen);
    mpack_write_int(&req->encoder, fenjie);
    mpack_write_int(&req->encoder, zuzhi);
    mpack_write_int(&req->encoder, yonghu);
    mpack_write_str(&req->encoder, ippre, strlen(ippre));

    return req_request(req);
}

int web_config_update_req(req_ctx_t * req)
{
    char * command = WEB_COMMAND_CONFIG_UPDATE;

    if (req == NULL) {
        return -EINVAL;
    }

    mpack_write_str(&req->encoder, command, strlen(command));

    return req_request(req);
}

int web_user_add_req(req_ctx_t * req, char *nid, char *stuno, char *name, char *idcode, int sex, char *tel, \
        char *phone, char *email, char *address, int onlinemax, char *passwd)
{
    char * command = WEB_COMMAND_USER_ADD;

    if (req == NULL) {
        return -EINVAL;
    }

    mpack_write_str(&req->encoder, command, strlen(command));
    mpack_write_str(&req->encoder, nid, strlen(nid));
    mpack_write_str(&req->encoder, stuno, strlen(stuno));
    mpack_write_str(&req->encoder, name, strlen(name));
    mpack_write_str(&req->encoder, idcode, strlen(idcode));
    mpack_write_int(&req->encoder, sex);
    mpack_write_str(&req->encoder, tel, strlen(tel));
    mpack_write_str(&req->encoder, phone, strlen(phone));
    mpack_write_str(&req->encoder, email, strlen(email));
    mpack_write_str(&req->encoder, address, strlen(address));
    mpack_write_int(&req->encoder, onlinemax);
    mpack_write_str(&req->encoder, passwd, strlen(passwd));

    return req_request(req);
}

int web_user_clear_req(req_ctx_t * req)
{
    char * command = WEB_COMMAND_USER_CLEAR;

    if (req == NULL) {
        return -EINVAL;
    }

    mpack_write_str(&req->encoder, command, strlen(command));

    return req_request(req);
}

int key_update_req(req_ctx_t * req)
{
    char * command = WEB_COMMAND_KEY_UPDATE;

    if (req == NULL) {
        return -EINVAL;
    }

    mpack_write_str(&req->encoder, command, strlen(command));

    return req_request(req);
}

int key_current_req(req_ctx_t * req)
{
    char * command = WEB_COMMAND_KEY_CURRENT;

    if (req == NULL) {
        return -EINVAL;
    }

    mpack_write_str(&req->encoder, command, strlen(command));

    return req_request(req);
}
