#include "libreq.h"
#include "libdiag.h"
#include "libapi.h"

req_ctx_t *g_trace_req = NULL;

int trace_req_init(void)
{
    g_trace_req = req_create("tracereq", WEBD_ADDRESS);
    if (g_trace_req == NULL) {
        DIAG_ERROR("create trace req failed.\n");
        return -ENOMEM;
    }

    return 0;
}

void trace_req_fini(void)
{
    req_destroy(g_trace_req);
}

int trace_add_va_req(req_ctx_t *req, int state, int level, char *fmt, va_list ap)
{
    int len = 0;
    char msg[256] = {0, };
    char *command = TRACE_COMMAND_EVENT_SEND;

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

int trace_event_req(req_ctx_t *req, int state, int level, char *fmt, ...)
{
    int ret;
    va_list ap;

    if (req == NULL) {
        return -EINVAL;
    }

    va_start(ap, fmt);
    ret = trace_add_va_req(req, state, level, fmt, ap);
    va_end(ap);

    return ret;
}

int domain_list_req(req_ctx_t * req, int page, int page_count)
{
    char * command = TRACE_COMMAND_DOMAIN_LIST;

    if (req == NULL) {
        return -EINVAL;
    }

    mpack_write_str(&req->encoder, command, strlen(command));
    mpack_write_int(&req->encoder, page);
    mpack_write_int(&req->encoder, page_count);

    return req_request(req);
}

int domain_add_req(req_ctx_t * req, char *ip, char *pref, int port, char *contacks, char *phone, char *position)
{
    char * command = TRACE_COMMAND_DOMAIN_ADD;

    if (req == NULL) {
        return -EINVAL;
    }

    mpack_write_str(&req->encoder, command, strlen(command));
    mpack_write_str(&req->encoder, ip, strlen(ip));
    mpack_write_str(&req->encoder, pref, strlen(pref));
    mpack_write_int(&req->encoder, port);
    mpack_write_str(&req->encoder, contacks, strlen(contacks));
    mpack_write_str(&req->encoder, phone, strlen(phone));
    mpack_write_str(&req->encoder, position, strlen(position));

    return req_request(req);
}

int domain_del_req(req_ctx_t * req, char *pref)
{
    char * command = TRACE_COMMAND_DOMAIN_DEL;

    if (req == NULL) {
        return -EINVAL;
    }

    mpack_write_str(&req->encoder, command, strlen(command));
    mpack_write_str(&req->encoder, pref, strlen(pref));

    return req_request(req);
}

int domain_search_req(req_ctx_t * req, char *pref)
{
    char * command = TRACE_COMMAND_DOMAIN_SEARCH;

    if (req == NULL) {
        return -EINVAL;
    }

    mpack_write_str(&req->encoder, command, strlen(command));
    mpack_write_str(&req->encoder, pref, strlen(pref));

    return req_request(req);
}

int domain_mod_req(req_ctx_t * req, char *ip, char *pref, int port, char *contacks, char *phone, char *position)
{
    char *command = TRACE_COMMAND_DOMAIN_MOD;

    if (req == NULL) {
        return -EINVAL;
    }

    mpack_write_str(&req->encoder, command, strlen(command));
    mpack_write_str(&req->encoder, ip, strlen(ip));
    mpack_write_str(&req->encoder, pref, strlen(pref));
    mpack_write_int(&req->encoder, port);
    mpack_write_str(&req->encoder, contacks, strlen(contacks));
    mpack_write_str(&req->encoder, phone, strlen(phone));
    mpack_write_str(&req->encoder, position, strlen(position));

    return req_request(req);
}

int userinfo_get_req(req_ctx_t * req, char *nidstr, char *remote_ip, int remote_port)
{
    char *command = TRACE_COMMAND_USERINFO_GET;

    if (req == NULL) {
        return -EINVAL;
    }

    mpack_write_str(&req->encoder, command, strlen(command));
    mpack_write_str(&req->encoder, nidstr, strlen(nidstr));
    mpack_write_str(&req->encoder, remote_ip, strlen(remote_ip));
    mpack_write_int(&req->encoder, remote_port);

    return req_request(req);
}

int get_nid_by_ipv6_req(req_ctx_t * req, char *ip, int preflen)
{
    char *command = TRACE_COMMAND_NID_GET;

    if (req == NULL) {
        return -EINVAL;
    }

    mpack_write_str(&req->encoder, command, strlen(command));
    mpack_write_str(&req->encoder, ip, strlen(ip));
    mpack_write_int(&req->encoder, preflen);

    return req_request(req);
}













