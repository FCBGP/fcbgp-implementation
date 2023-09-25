#include "libreq.h"
#include "libdiag.h"
#include "libapi.h"

req_ctx_t *g_gen_addr_req = NULL;

int gen_addr_req_init(void)
{
    g_gen_addr_req = req_create("gen_addrreq", GEN_ADDRD_ADDRESS);
    if (g_gen_addr_req == NULL) {
        DIAG_ERROR("create gen_addr req failed.\n");
        return -ENOMEM;
    }

    return 0;
}

void gen_addr_req_fini(void)
{
    req_destroy(g_gen_addr_req);
}

int gen_addr_version_req(req_ctx_t *req)
{
    char *command = GEN_ADDR_COMMAND_VERSION;

    if (req == NULL) {
        return -EINVAL;
    }

    mpack_write_str(&req->encoder, command, strlen(command));

    return req_request(req);
}

int nid_query_req(req_ctx_t *req, char *nid)
{
    char *command = GEN_ADDR_COMMAND_NID_QUERY;

    if (req == NULL) {
        return -EINVAL;
    }

    mpack_write_str(&req->encoder, command, strlen(command));
    mpack_write_str(&req->encoder, nid, strlen(nid));

    return req_request(req);
}

int nid_gen_req(req_ctx_t *req, char *stuno)
{
    char *command = GEN_ADDR_COMMAND_NID_GEN;

    if (req == NULL || stuno == NULL) {
        return -EINVAL;
    }

    mpack_write_str(&req->encoder, command, strlen(command));
    mpack_write_str(&req->encoder, stuno, strlen(stuno));

    return req_request(req);
}

int nid_get_req(req_ctx_t *req, char *stuno)
{
    char *command = GEN_ADDR_COMMAND_NID_GET_BY_STUNO;

    if(req == NULL || stuno == NULL) {
        return -EINVAL;
    }

    mpack_write_str(&req->encoder, command, strlen(command));
    mpack_write_str(&req->encoder, stuno, strlen(stuno));

    return req_request(req);
}

int ipv6_gen_req(req_ctx_t * req, char *nid)
{
    char * command = GEN_ADDR_COMMAND_IPV6_GEN;

    if (req == NULL) {
        return -EINVAL;
    }

    mpack_write_str(&req->encoder, command, strlen(command));
    mpack_write_str(&req->encoder, nid, strlen(nid));

    return req_request(req);
}

int nid_delete_req(req_ctx_t * req, char *nid)
{
    char * command = GEN_ADDR_COMMAND_NID_DELETE;

    if (req == NULL) {
        return -EINVAL;
    }

    mpack_write_str(&req->encoder, command, strlen(command));
    mpack_write_str(&req->encoder, nid, strlen(nid));

    return req_request(req);
}

int client_user_info_req(req_ctx_t * req, char *nid, char *address)
{
    char * command = GEN_ADDR_COMMAND_CLIENT_USER_INFO;

    if (req == NULL) {
        return -EINVAL;
    }

    mpack_write_str(&req->encoder, command, strlen(command));
    mpack_write_str(&req->encoder, nid, strlen(nid));
    mpack_write_str(&req->encoder, address, strlen(address));

    return req_request(req);
}

int client_user_recharge_req(req_ctx_t * req, char *nid, unsigned int amount)
{
    char *command = GEN_ADDR_COMMAND_CLIENT_USER_RECHARGE;

    if (req == NULL) {
        return -EINVAL;
    }

    mpack_write_str(&req->encoder, command, strlen(command));
    mpack_write_str(&req->encoder, nid, strlen(nid));
    mpack_write_uint(&req->encoder, amount);

    return req_request(req);

}

int history_get_bynid_req(req_ctx_t * req, char * nid, int page, int perPage, char *start_time, char *end_time)
{
    char *command = GEN_ADDR_COMMAND_HISTORY;

    if (req == NULL) {
        return -EINVAL;
    }

    mpack_write_str(&req->encoder, command, strlen(command));
    mpack_write_str(&req->encoder, nid, strlen(nid));
    mpack_write_int(&req->encoder, page);
    mpack_write_int(&req->encoder, perPage);
    mpack_write_str(&req->encoder, start_time, strlen(start_time));
    mpack_write_str(&req->encoder, end_time, strlen(end_time));

    return req_request(req);
}

int nid_get_by_addr_req(req_ctx_t * req, char *ipv6)
{
    //nid_get_by_ipv6_rep
    char * command = GEN_ADDR_COMMAND_NID_GET_BY_IPV6;

    if (req == NULL) {
        return -EINVAL;
    }

    mpack_write_str(&req->encoder, command, strlen(command));
    mpack_write_str(&req->encoder, ipv6, strlen(ipv6));

    return req_request(req);
}

int ipv6_release_req(req_ctx_t * req, char *addr)
{
    char * command = GEN_ADDR_COMMAND_IPV6_RELEASE;

    if (req == NULL) {
        return -EINVAL;
    }

    mpack_write_str(&req->encoder, command, strlen(command));
    mpack_write_str(&req->encoder, addr, strlen(addr));

    return req_request(req);
}

/*
int config_show_req(req_ctx_t * req)
{
    char * command = GEN_ADDR_COMMAND_CONFIG_SHOW;

    if (req == NULL) {
        return -EINVAL;
    }

    mpack_write_str(&req->encoder, command, strlen(command));

    return req_request(req);
}

int config_reset_req(req_ctx_t * req, int nidlen, int fenjie, int zuzhi, int yonghu, char *ippre)
{
    char * command = GEN_ADDR_COMMAND_CONFIG_RESET;
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

int config_update_req(req_ctx_t * req)
{
    char * command = GEN_ADDR_COMMAND_CONFIG_UPDATE;

    if (req == NULL) {
        return -EINVAL;
    }

    mpack_write_str(&req->encoder, command, strlen(command));

    return req_request(req);
}
*/

int user_add_req(req_ctx_t * req, char *nid, char *stuno, char *name, char *idcode, int sex, char *tel, \
        char *phone, char *email, char *address, int onlinemax, char *passwd)
{
    char * command = GEN_ADDR_COMMAND_USER_ADD;

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

int user_clear_req(req_ctx_t * req)
{
    char * command = GEN_ADDR_COMMAND_USER_CLEAR;

    if (req == NULL) {
        return -EINVAL;
    }

    mpack_write_str(&req->encoder, command, strlen(command));

    return req_request(req);
}


