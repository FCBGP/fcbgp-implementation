#include "librep.h"
#include "libdiag.h"

#include "fooapi.h"

rep_ctx_t *g_foo_rep = NULL;

int foo_rep_init(void)
{
    g_foo_rep = rep_create("food", 1, FOOD_ADDRESS);
    if (g_foo_rep == NULL) {
        DIAG_ERROR("create foo rep failed.\n");
        return -ENOMEM;
    }

    return 0;
}

int foo_rep_register(dispatch_command_t *commands)
{
    return dispatch_register_commands(g_foo_rep->dispatch, commands);
}

int foo_rep_start(void)
{
    return rep_start(g_foo_rep);
}

void foo_rep_loop(void)
{
    rep_loop(g_foo_rep);
}

void foo_rep_fini(void)
{
    rep_destroy(g_foo_rep);
}

int foo_add_rep(rep_worker_t *worker)
{
    int ret = 0;
    int num = 0;
    char str[32] = {0, };
    uint32_t slen = sizeof(str);

    ret = mpack_read_int(&worker->decoder, &num);
    if (!ret) {
        DIAG_ERROR("unpack arg number failed: %s\n", mpack_strerror(&worker->decoder));
        return -EBADMSG;
    }

    ret = mpack_read_str(&worker->decoder, str, &slen);
    if (!ret) {
        DIAG_ERROR("unpack arg string failed: %s\n", mpack_strerror(&worker->decoder));
        return -EBADMSG;
    }

    DIAG_DEBUG("foo add {%d, %s}\n", num, str);

    return rep_sendok(worker, "done");
}

int foo_del_rep(rep_worker_t *worker)
{
    int ret = 0;
    int num = 0;
    char str[32] = {0, };
    uint32_t slen = sizeof(str);

    ret = mpack_read_int(&worker->decoder, &num);
    if (!ret) {
        DIAG_ERROR("unpack arg number failed: %s\n", mpack_strerror(&worker->decoder));
        return -EBADMSG;
    }

    ret = mpack_read_str(&worker->decoder, str, &slen);
    if (!ret) {
        DIAG_ERROR("unpack arg string failed: %s\n", mpack_strerror(&worker->decoder));
        return -EBADMSG;
    }

    DIAG_DEBUG("foo del {%d, %s}\n", num, str);

    return rep_sendok(worker, "done");
}

int foo_tty_rep(rep_worker_t *worker)
{
    int ret = 0;
    char str[32] = {0, };
    uint32_t slen = sizeof(str);

    ret = mpack_read_str(&worker->decoder, str, &slen);
    if (!ret) {
        DIAG_ERROR("unpack arg tty failed: %s\n", mpack_strerror(&worker->decoder));
        return -EBADMSG;
    }

    DIAG_DEBUG("foo tty {%s}\n", str);

    FILE *fp = fopen(str, "w");
    if (fp) {
        fprintf(fp, "Hello World!\n");
        fclose(fp);
    }

    return rep_sendok(worker, "done");
}

dispatch_command_t g_foo_commands[] = {
    {FOO_COMMAND_ADD, foo_add_rep},
    {FOO_COMMAND_DEL, foo_del_rep},
    {FOO_COMMAND_TTY, foo_tty_rep},

    {NULL, NULL},
};
