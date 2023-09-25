#include "libreq.h"
#include "libdiag.h"
#include "libapi.h"

req_ctx_t *g_NIDTGA_snmp_req = NULL;

int NIDTGA_snmp_req_init(void)
{
    g_NIDTGA_snmp_req = req_create("NIDTGA_snmpreq", NIDTGA_SNMPD_ADDRESS);
    if (g_NIDTGA_snmp_req == NULL) {
        DIAG_ERROR("create NIDTGA_snmp req failed.\n");
        return -ENOMEM;
    }

    return 0;
}

void NIDTGA_snmp_req_fini(void)
{
    req_destroy(g_NIDTGA_snmp_req);
}

int NIDTGA_snmp_version_req(req_ctx_t *req)
{
    char *command = NIDTGA_SNMP_COMMAND_VERSION;

    if (req == NULL) {
        return -EINVAL;
    }

    mpack_write_str(&req->encoder, command, strlen(command));

    return req_request(req);
}

int NIDTGA_snmp_devdesc_req(req_ctx_t *req, char *ip, int port, char *comm)
{
    char *command = NIDTGA_SNMP_COMMAND_DEVDESC;

    if (req == NULL) {
        return -EINVAL;
    }

    mpack_write_str(&req->encoder, command, strlen(command));
    mpack_write_str(&req->encoder, ip, strlen(ip));
    mpack_write_int(&req->encoder, port);
    mpack_write_str(&req->encoder, comm, strlen(comm));

    return req_request(req);
}

int NIDTGA_snmp_cpu_5sec_req(req_ctx_t *req, char *ip, int port, char *comm)
{
    char *command = NIDTGA_SNMP_COMMAND_CPU_5SEC;

    if (req == NULL) {
        return -EINVAL;
    }

    mpack_write_str(&req->encoder, command, strlen(command));
    mpack_write_str(&req->encoder, ip, strlen(ip));
    mpack_write_int(&req->encoder, port);
    mpack_write_str(&req->encoder, comm, strlen(comm));

    return req_request(req);
}

int NIDTGA_snmp_cpu_1min_req(req_ctx_t *req, char *ip, int port, char *comm)
{
    char *command = NIDTGA_SNMP_COMMAND_CPU_1MIN;

    if (req == NULL) {
        return -EINVAL;
    }

    mpack_write_str(&req->encoder, command, strlen(command));
    mpack_write_str(&req->encoder, ip, strlen(ip));
    mpack_write_int(&req->encoder, port);
    mpack_write_str(&req->encoder, comm, strlen(comm));

    return req_request(req);
}

int NIDTGA_snmp_cpu_5min_req(req_ctx_t *req, char *ip, int port, char *comm)
{
    char *command = NIDTGA_SNMP_COMMAND_CPU_5MIN;

    if (req == NULL) {
        return -EINVAL;
    }

    mpack_write_str(&req->encoder, command, strlen(command));
    mpack_write_str(&req->encoder, ip, strlen(ip));
    mpack_write_int(&req->encoder, port);
    mpack_write_str(&req->encoder, comm, strlen(comm));

    return req_request(req);
}

int NIDTGA_snmp_mem_used_req(req_ctx_t *req, char *ip, int port, char *comm)
{
    char *command = NIDTGA_SNMP_COMMAND_MEM_USED;

    if (req == NULL) {
        return -EINVAL;
    }

    mpack_write_str(&req->encoder, command, strlen(command));
    mpack_write_str(&req->encoder, ip, strlen(ip));
    mpack_write_int(&req->encoder, port);
    mpack_write_str(&req->encoder, comm, strlen(comm));

    return req_request(req);
}

int NIDTGA_snmp_mem_free_req(req_ctx_t *req, char *ip, int port, char *comm)
{
    char *command = NIDTGA_SNMP_COMMAND_MEM_FREE;

    if (req == NULL) {
        return -EINVAL;
    }

    mpack_write_str(&req->encoder, command, strlen(command));
    mpack_write_str(&req->encoder, ip, strlen(ip));
    mpack_write_int(&req->encoder, port);
    mpack_write_str(&req->encoder, comm, strlen(comm));

    return req_request(req);
}

int NIDTGA_snmp_sys_uptime_req(req_ctx_t *req, char *ip, int port, char *comm)
{
    char *command = NIDTGA_SNMP_COMMAND_SYS_UPTIME;

    if (req == NULL) {
        return -EINVAL;
    }

    mpack_write_str(&req->encoder, command, strlen(command));
    mpack_write_str(&req->encoder, ip, strlen(ip));
    mpack_write_int(&req->encoder, port);
    mpack_write_str(&req->encoder, comm, strlen(comm));

    return req_request(req);
}

int NIDTGA_snmp_sys_contact_req(req_ctx_t *req, char *ip, int port, char *comm)
{
    char *command = NIDTGA_SNMP_COMMAND_SYS_CONTACT;

    if (req == NULL) {
        return -EINVAL;
    }

    mpack_write_str(&req->encoder, command, strlen(command));
    mpack_write_str(&req->encoder, ip, strlen(ip));
    mpack_write_int(&req->encoder, port);
    mpack_write_str(&req->encoder, comm, strlen(comm));

    return req_request(req);
}

int NIDTGA_snmp_sys_name_req(req_ctx_t *req, char *ip, int port, char *comm)
{
    char *command = NIDTGA_SNMP_COMMAND_SYS_NAME;

    if (req == NULL) {
        return -EINVAL;
    }

    mpack_write_str(&req->encoder, command, strlen(command));
    mpack_write_str(&req->encoder, ip, strlen(ip));
    mpack_write_int(&req->encoder, port);
    mpack_write_str(&req->encoder, comm, strlen(comm));

    return req_request(req);
}

int NIDTGA_snmp_sys_location_req(req_ctx_t *req, char *ip, int port, char *comm)
{
    char *command = NIDTGA_SNMP_COMMAND_SYS_LOCATION;

    if (req == NULL) {
        return -EINVAL;
    }

    mpack_write_str(&req->encoder, command, strlen(command));
    mpack_write_str(&req->encoder, ip, strlen(ip));
    mpack_write_int(&req->encoder, port);
    mpack_write_str(&req->encoder, comm, strlen(comm));

    return req_request(req);
}

int NIDTGA_snmp_if_info_req(req_ctx_t *req, char *ip, int port, char *comm)
{
    char *command = NIDTGA_SNMP_COMMAND_IF_INFO;

    if (req == NULL) {
        return -EINVAL;
    }

    mpack_write_str(&req->encoder, command, strlen(command));
    mpack_write_str(&req->encoder, ip, strlen(ip));
    mpack_write_int(&req->encoder, port);
    mpack_write_str(&req->encoder, comm, strlen(comm));

    return req_request(req);
}
