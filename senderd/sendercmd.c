#include "libreq.h"
#include "libdiag.h"
#include "libcmd.h"
#include "libapi.h"
#include "libmbs.h"

#include "reqapi.h"

int do_version(app_t * app, cmdline_t * cmdline)
{
    int ret = -1;
    var_boolean_t *format = app_param_get(app, "format");

    ret = sender_version_req(g_sender_req);
    if (ret < 0) {
        goto out;
    }

    mpack_ctx_dump(NULL, &g_sender_req->decoder, format ? 1 : 0);

    ret = 0;
out:
    app_param_destroy(format);
    return ret;
}

int do_sender(app_t *app, cmdline_t * cmdline)
{
    int ret = -1;

    var_boolean_t * format = app_param_get(app, "format");

    app_add_cmdline(app, SENDER_COMMAND_SEND",[file],[ipver],[srcip],[dstip],[proto],[count],[interval],[format]", do_sender, "To begin sending packets using a JSON file, the default directory is '/usr/local/etc'.");
    var_string_t * pfile = app_param_get(app, "file");
    char *file = pfile ? *pfile : NULL;

    var_string_t * pipver = app_param_get(app, "ipver");
    char *ipver = pipver ? *pipver : NULL;

    var_string_t * psrcip = app_param_get(app, "srcip");
    char *srcip = psrcip ? *psrcip : NULL;

    var_string_t * pdstip = app_param_get(app, "dstip");
    char *dstip = pdstip ? *pdstip : NULL;

    var_string_t * pproto = app_param_get(app, "proto");
    char *proto = pproto ? *pproto : NULL;

    var_uint_t * pcount = app_param_get(app, "count");
    unsigned int count = pcount ? *pcount : 3;
    var_uint_t * pinterval = app_param_get(app, "interval");
    unsigned int interval = pinterval ? *pinterval : 0;

    ret = sender_send_req(g_sender_req, file, ipver, srcip, dstip, proto, count, interval);
    if (ret < 0) {
        DIAG_ERROR("send packets failed.\n");
        goto out;
    }

    mpack_ctx_dump(NULL, &g_sender_req->decoder, format ? 1 : 0);
out:
    app_param_destroy(format);
    app_param_destroy(pfile);
    app_param_destroy(pipver);
    app_param_destroy(psrcip);
    app_param_destroy(pdstip);
    app_param_destroy(pproto);
    app_param_destroy(pcount);
    app_param_destroy(pinterval);
    return ret;
}

int main(int argc, char** argv)
{
    int ret;

    app_t *app = app_create("sender_cmd",
            "0.1",
            "writen by zhanght, just a test",
            "zhanght<zhang.hui.tao@163.com>",
            "sender_cmd is a program which can issue command to senderd."
            );
    //option
    app_add_option(app, 'f', "format", NULL, 0, "do you want to format the output?");
    app_add_option(app, -1, "file", "string", 0, "provide a file for sendind pkt.");
    app_add_option(app, -1, "ipver", "string", 0, "ipv4 or ipv6.");
    app_add_option(app, -1, "srcip", "string", 0, "provide an ipaddress must matches the ipversion specified.");
    app_add_option(app, -1, "dstip", "string", 0, "provide an ipaddress must matches the ipversion specified.");
    app_add_option(app, -1, "proto", "string", 0, "udp or tcp.");
    app_add_option(app, -1, "count", "uint", 0, "how many times would you like the packet to be sended.");
    app_add_option(app, -1, "interval", "uint", 0, "the interval between sending two packets in microseconds.");
#if 0
    app_add_option(app, -1, "nidlen", "uint", 0, "nid length");
#endif

    app_add_option(app, -1, SENDER_COMMAND_VERSION, NULL, 0, "show version info of senderd.");
    app_add_option(app, -1, SENDER_COMMAND_SEND, NULL, 0, "To begin sending packets using a JSON file, the default directory is '/usr/local/etc'");
    app_add_option(app, -1, SENDER_COMMAND_RECV, NULL, 0, "i haven't decided it so far");
    app_add_option(app, -1, SENDER_COMMAND_STAT, NULL, 0, "i haven't decided it so far.");

#if 0
    app_add_option(app, -1, SENDER_COMMAND_NID_QUERY, "string", 0, "query nid.");
    app_add_option(app, -1, SENDER_COMMAND_IPV6_GEN, NULL, 0, "generate ipv6 address.");
#endif

    //cmdline
    app_add_cmdline(app, SENDER_COMMAND_VERSION",[format]", do_version, "show version info in senderd.");
    app_add_cmdline(app, SENDER_COMMAND_SEND",[file],[ipver],[srcip],[dstip],[proto],[count],[interval],[format]", do_sender, "To begin sending packets using a JSON file, the default directory is '/usr/local/etc'.");

//    app_add_cmdline(app, SENDER_COMMAND_USER_ADD",[nid],[stuno],[name],[idcode],[sex],[tel],[phone],[email],[address],[onlinemax],passwd,[format]", do_user_add, "user add.");

    mbsinit(0);
    sender_req_init();

    ret = app_run(app, argc, argv);

    sender_req_fini();

    mbsfini();

    app_destroy(app);

    return ret;
}

