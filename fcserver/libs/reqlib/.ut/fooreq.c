#include "libdiag.h"
#include "libreq.h"

#include "fooapi.h"

req_ctx_t* g_foo_req = NULL;

int foo_req_init(void)
{
    g_foo_req = req_create("fooreq", FOOD_ADDRESS);
    if (g_foo_req == NULL)
    {
        DIAG_ERROR("create foo req failed.\n");
        return -ENOMEM;
    }

    return 0;
}

void foo_req_fini(void) { req_destroy(g_foo_req); }

int foo_add_req(req_ctx_t* req, int num, char* str)
{
    char* command = FOO_COMMAND_ADD;

    mpack_write_str(&req->encoder, command, strlen(command));
    mpack_write_int(&req->encoder, num);
    mpack_write_str(&req->encoder, str, strlen(str));

    return req_request(req);
}

int foo_del_req(req_ctx_t* req, int num, char* str)
{
    char* command = FOO_COMMAND_DEL;

    mpack_write_str(&req->encoder, command, strlen(command));
    mpack_write_int(&req->encoder, num);
    mpack_write_str(&req->encoder, str, strlen(str));

    return req_request(req);
}

int foo_tty_req(req_ctx_t* req, char* tty)
{
    char* command = FOO_COMMAND_TTY;

    mpack_write_str(&req->encoder, command, strlen(command));
    mpack_write_str(&req->encoder, tty, strlen(tty));

    return req_request(req);
}
