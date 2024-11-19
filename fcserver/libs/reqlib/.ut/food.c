#include "libcmd.h"
#include "libstring.h"
#include "libsysmgr.h"
#include "libcache.h"
#include "libdiag.h"

#include "fooapi.h"
#include "foorep.h"

int food_init(void)
{
    int ret;

    diag_init("food");

    ret = cache_init();
    if (ret < 0) {
        goto cache_init_failed;
    }

    ret = mbsinit(0);
    if (ret < 0) {
        DIAG_ERROR("mbs init failed.\n");
        goto mbs_init_failed;
    }

    ret = foo_rep_init();
    if (ret < 0) {
        goto foo_rep_init_failed;
    }

    return 0;
foo_rep_init_failed:
    mbsfini();
mbs_init_failed:
    cache_fini();
cache_init_failed:
    diag_fini();
    return ret;
}

void food_fini(void)
{
    foo_rep_fini();
    mbsfini();
    cache_fini();
    diag_fini();
}

void sighandler(int sig)
{
    if (sig == SIGTERM || sig == SIGSEGV || sig == SIGFPE || sig == SIGILL
#ifdef PRJ_SUPPORT_DEBUG
            || sig == SIGINT
#endif
            || sig == SIGBUS || sig ==SIGSYS || sig == SIGURG) {
        DIAG_WARNING("food(%d) will exit by signal %d\n", getpid(), sig);
        food_fini();

#ifdef PRJ_SUPPORT_COREDUMP
        /* raise this signal again, then we can get the coredump file.*/
        signal(sig, SIG_DFL);
        raise(sig);
#else
        exit(EXIT_FAILURE);
#endif
    } else {
        if (sig == SIGCHLD) // don't output log as too many such signal.
            return;
        DIAG_WARNING("food received signal %d, we will ignore it.\n", sig);
        return;
    }
}

int do_dump_version(app_t * app, cmdline_t * cmdline)
{
    printf("v%s", PRJ_VERSION);
    return 0;
}

int do_app_daemonize(app_t * app, cmdline_t * cmdline)
{
    int ret;
    var_boolean_t *foreground = app_param_get(app, "foreground");

    if (foreground) {
        diag_foreground_set(1);
        ret = 1;
    } else {
        ret = app_daemonize(app, cmdline);
    }

    app_param_destroy(foreground);
    return ret;
}

int parse_cmdline(int argc, char** argv)
{
    int ret;

    app_t *app = app_create("food",
            PRJ_VERSION,
            PRJ_COPYRIGHT,
            "liaoxf<liaofei1128@163.com>",
            "food is a daemon program to control foo."
            );

    app_add_option(app, 'v', "dumpversion", NULL, 0, "print the version string");
    app_add_option(app, 'f', "foreground", NULL, 0, "run food in foreground");
    app_add_option(app, 'D', "daemonize", NULL, 0, "run the application as a daemon");

    app_add_cmdline(app, "dumpversion", do_dump_version, "print the version string");
    app_add_cmdline(app, "daemonize", do_app_daemonize, "run the application as a daemon");
    app_add_cmdline(app, "foreground", do_app_daemonize, "run the application in foreground");

    ret = app_run(app, argc, argv);

    app_destroy(app);
    return ret;
}

int main(int argc, char *argv[])
{
    int i;
    int ret;

    for (i=0; i<NSIG; i++) {
        if (i != SIGKILL && i != SIGSTOP) {
            signal(i, sighandler);
        }
    }

    if (parse_cmdline(argc, argv) <= 0) {
        return 0;
    }

    if (sys_check_process("food")) {
        return 0;
    }

    ret = food_init();
    if (ret < 0) {
        return ret;
    }

    foo_rep_register(g_foo_commands);

    foo_rep_start();
    foo_rep_loop();

    food_fini();
    return 0;
}

