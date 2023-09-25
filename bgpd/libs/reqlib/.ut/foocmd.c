#include "libreq.h"
#include "libcmd.h"
#include "libmbs.h"
#include "libdiag.h"

#include "fooapi.h"
#include "fooreq.h"

int do_foo_add(app_t * app, cmdline_t * cmdline)
{
    int ret = -1;
    var_boolean_t *format = app_param_get(app, "format");
    var_int_t *num = app_param_get(app, "num");
    var_string_t *str = app_param_get(app, "str");

    ret = foo_add_req(g_foo_req, *num, *str);
    if (ret < 0) {
        goto out;
    }

    mpack_ctx_dump(NULL, &g_foo_req->decoder, format ? 1 : 0);

    ret = 0;
out:
    app_param_destroy(format);
    app_param_destroy(num);
    app_param_destroy(str);
    return ret;
}

int do_foo_del(app_t * app, cmdline_t * cmdline)
{
    int ret = -1;
    var_boolean_t *format = app_param_get(app, "format");
    var_int_t *num = app_param_get(app, "num");
    var_string_t *str = app_param_get(app, "str");

    ret = foo_del_req(g_foo_req, *num, *str);
    if (ret < 0) {
        goto out;
    }

    mpack_ctx_dump(NULL, &g_foo_req->decoder, format ? 1 : 0);

    ret = 0;
out:
    app_param_destroy(format);
    app_param_destroy(num);
    app_param_destroy(str);
    return ret;
}

int do_foo_tty(app_t * app, cmdline_t * cmdline)
{
    int ret = -1;
    var_boolean_t *format = app_param_get(app, "format");

    char *tty = ttyname(STDIN_FILENO);
    if (tty == NULL) {
        goto out;
    }

    ret = foo_tty_req(g_foo_req, tty);
    if (ret < 0) {
        goto out;
    }

    mpack_ctx_dump(NULL, &g_foo_req->decoder, format ? 1 : 0);

    ret = 0;
out:
    app_param_destroy(format);
    return ret;
}

int main(int argc, char** argv)
{
    int ret;

    app_t *app = app_create("foocmd",
            PRJ_VERSION,
            PRJ_COPYRIGHT,
            "gbj<gaobj021@163.com>,"
            "liaoxf<liaofei1128@163.com>",
            "foocmd is a program which can issue command to food."
            );

    app_add_option(app, 'f', "format", NULL, 0, "do you want to format the output?");
    app_add_option(app, -1, "num", "int", 0, "the argument number.");
    app_add_option(app, -1, "str", "string", 0, "the argument string.");

    app_add_option(app, -1, FOO_COMMAND_ADD, NULL, 0, "foo add.");
    app_add_option(app, -1, FOO_COMMAND_DEL, NULL, 0, "foo del.");
    app_add_option(app, -1, FOO_COMMAND_TTY, NULL, 0, "pass the tty name to food.");

    app_add_cmdline(app, FOO_COMMAND_ADD",num,str,[format]", do_foo_add, "foo add.");
    app_add_cmdline(app, FOO_COMMAND_DEL",num,str,[format]", do_foo_del, "foo del.");
    app_add_cmdline(app, FOO_COMMAND_TTY",[format]", do_foo_tty, "pass the tty name to food.");

    mbsinit(0);
    foo_req_init();

    ret = app_run(app, argc, argv);

    foo_req_fini();
    mbsfini();

    app_destroy(app);
    return ret;
}

