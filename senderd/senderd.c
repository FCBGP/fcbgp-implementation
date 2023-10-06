#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "libdiag.h"
#include "libcmd.h"
#include "reqapi.h"
#include "libthread.h"
#include "libstring.h"
#include "libcache.h"
#include "libmbs.h"
#include "libsysmgr.h"

#include "senderd.h"
#include "sender_rep.h"

int do_dump_version(app_t * app, cmdline_t * cmdline)
{
    printf("%s", "0.1");
    return 0;
}

int do_app_daemonize(app_t * app, cmdline_t * cmdline)
{
    int ret;
    var_int_t *level = app_param_get(app, "level");
    var_boolean_t *foreground = app_param_get(app, "foreground");

    if (level) {
        diag_level_set(*level);
    }

    if (foreground) {
        diag_foreground_set(1);
        ret = 1;
    } else {
        ret = app_daemonize(app, cmdline);
    }

    app_param_destroy(level);
    app_param_destroy(foreground);
    return ret;
}

#if 0
int do_app_config(app_t * app, cmdline_t * cmdline)
{
    int ret;
    char *p = NULL;
    FILE *fp = NULL;
    char temp[256] = {0, };
    char ip[64] = {0, };
    char user[64] = {0, };
    char passwd[32] = {0, };
    char database[64] = {0, };
    int port = 0;

    char *key = NULL;
    char *value = NULL;


    var_string_t *path = app_param_get(app, "config");
    if (!strcmp(*path, "export")) {
        char conf[] = "mysql_ip 127.0.0.1\nlogin_name nidtga\npasswd NIDTGA_802.1x\ndatabase campus6\nport 3306";
        FILE *fp;
        fp = fopen("./sender.config", "w+");
        if (fp == NULL) {
            printf("file open failed.\n");
            return -1;
        }

        ret = fwrite(conf, 1, sizeof(conf)-1, fp);
        if (ret != sizeof(conf)-1) {
            printf("fwrite failed.\n");
            return -1;
        }
        fclose(fp);
        return 0;
    }

    fp = fopen(*path, "rw");
    if (fp == NULL) {
        //DIAG_ERROR("open %s failed.\n", *path);
        return -1;
    }

    p = fgets(temp, sizeof(temp), fp);
    while (p != NULL) {
        if (*p == '\n') {
            p = fgets(temp, sizeof(temp), fp);
            continue;
        }

        p = strtok(temp, " ");
        key = p;
        p = strtok(NULL, " ");
        value = p;
        value[strlen(p)-1] = '\0';

        if (!strcmp(key, "mysql_ip")) {
            strncpy(ip, value, sizeof(ip)-1);
        } else if (!strcmp(key, "login_name")) {
            strncpy(user, value, sizeof(user)-1);
        } else if (!strcmp(key, "passwd")) {
            strncpy(passwd, value, sizeof(passwd)-1);
        } else if (!strcmp(key, "database")) {
            strncpy(database, value, sizeof(database)-1);
        } else if (!strcmp(key, "port")) {
            port = atoi(value);
        }
        p = fgets(temp, sizeof(temp), fp);
    }

    ret = mysql_ctx_update(strcmp(ip, "") ? ip : NULL,
            strcmp(user, "") ? user : NULL,
            strcmp(passwd, "") ? passwd : NULL,
            strcmp(database, "") ? database: NULL,
            port);
    if (ret < 0) {
        return ret;
    }

    app_daemonize(app, cmdline);
    app_param_destroy(path);
    return 1;
}
#endif

int parse_cmdline(int argc, char** argv)
{
    int ret;

    app_t *app = app_create("senderd",
            "0.1",
            "just a test",
            "zhanghuitao<zhang.hui.tao@163.com>",
            "senderd is a daemon program to generate ipv6 address for kea-dhcp."
            );

    app_add_option(app, 'v', "dumpversion", NULL, 0, "print the version string");
    app_add_option(app, 'f', "foreground", NULL, 0, "run sysmgrd in foreground");
    app_add_option(app, 'D', "daemonize", NULL, 0, "run the application as a daemon");
    app_add_option(app, 'l', "level", "int", 0, "application diagnose level(0: emerg, 1: error, 2: warning, 3: debug, 5: verbose)");
    app_add_option(app, 'c', "config", "string", 0, "application diagnose level(0: emerg, 1: error, 2: warning, 3: debug, 5: verbose)");

    app_add_cmdline(app, "dumpversion", do_dump_version, "print the version string");
    app_add_cmdline(app, "daemonize,[level]", do_app_daemonize, "run the application as a daemon");
    app_add_cmdline(app, "foreground,[level]", do_app_daemonize, "run the application in foreground");
//    app_add_cmdline(app, "config", do_app_config, "run the application mysql config ");

    ret = app_run(app, argc, argv);

    app_destroy(app);
    return ret;
}

int senderd_init(void)
{
    int ret;

    diag_init("senderd");

    ret = cache_init();
    if (ret < 0) {
        goto cache_init_failed;
    }

    ret = mbsinit(10, 10240, 4096, 4096, 512, 512, 256, 256, 64, 64, 16);
    if (ret < 0) {
        DIAG_ERROR("mbs init failed.\n");
        goto mbs_init_failed;
    }

    ret = sender_rep_init();
    if (ret < 0) {
        DIAG_ERROR("senderd reply server init failed.\n");
        goto sender_rep_init_failed;
    }

    return 0;
sender_rep_init_failed:
    mbsfini();
mbs_init_failed:
    cache_fini();
cache_init_failed:
    diag_fini();
    return ret;
}

void senderd_fini(void)
{
    sender_rep_fini();
    mbsfini();
    cache_fini();
    diag_fini();
    return;
}

void sighandler(int sig)
{
    if (sig == SIGTERM || sig == SIGSEGV || sig == SIGFPE || sig == SIGILL
#ifdef PRJ_SUPPORT_DEBUG
            || sig == SIGINT
#endif
            || sig == SIGBUS || sig ==SIGSYS || sig == SIGURG) {
        DIAG_WARNING("senderd(%d) will exit by signal %d\n", getpid(), sig);
        diag_backtrace();
        senderd_fini();

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
        DIAG_WARNING("senderd received signal %d, we will ignore it.\n", sig);
        return;
    }
}

int main(int argc, char *argv[])
{
    int i;
    int ret;

    for (i = 0; i < NSIG; i++) {
        signal(i, sighandler);
    }

    argc = 2;
    strncpy(argv[1],"-D", sizeof("-D"));

    ret = parse_cmdline(argc, argv);
    if (ret <= 0) {
        return ret;
    }

   if (sys_check_process("senderd")) {
       return -EEXIST;
   }

    ret = senderd_init();
    if (ret < 0) {
        return ret;
    }

    ncs_sender_init();

    sender_rep_register(g_sender_commands);

    sender_rep_start();
    sender_rep_loop();

    senderd_fini();

    return 0;
}
