#include "libcmd.h"
#include "libstring.h"

typedef struct var_date_st {
    int year;
    int month;
    int day;
} var_date_t;

int parse_date(char *arg, var_date_t *result)
{
    int ret = -1;
    int year, month, day;

    if (!arg || !result) {
        goto out;
    }

    if (sscanf(arg, "%d-%d-%d", &year, &month, &day) != 3) {
        if (sscanf(arg, "%d/%d/%d", &year, &month, &day) != 3) {
            goto out;
        }
    }

    if (year < 0 || month < 0 || month > 12 || day < 0 ||day > 31) {
        goto out;
    }

    if (month == 2) {
        if ((year % 400) == 0 || ((year % 100) && (year % 4) == 0)) {
            if (day > 29) {
                goto out;
            }
        } else {
            if (day > 28) {
                goto out;
            }
        }
    }

    result->year = year;
    result->month = month;
    result->day = day;

    ret = 0;
out:
    return ret;
}

int do_process(app_t * app, cmdline_t * cmdline)
{
    int ret = -1;
    var_int_t *arg0 = app_param_get(app, "arg0");
    var_string_t *arg1 = app_param_get(app, "arg1");
    var_ipaddr4_t *arg2 = app_param_get(app, "arg2");
    var_boolean_t *arg3 = app_param_get(app, "arg3");
    var_ethaddr_t *arg4 = app_param_get(app, "arg4");
    var_cidraddr4_t *arg5 = app_param_get(app, "arg5");

    printf("arg0='%d'\n", *arg0);
    printf("arg1='%s'\n", *arg1);
    if (arg2) {
        printf("arg2='%08x'\n", arg2->u.addr32);
    }

    printf("arg3=%s\n", arg3 ? "true" : "false");

    while (arg4) {
        printf("arg4="ETHADDRFMT"\n", arg4->mac[0], arg4->mac[1], arg4->mac[2], arg4->mac[3], arg4->mac[4], arg4->mac[5]);
        app_param_destroy(arg4);

        arg4 = app_param_get(app, "arg4");
    }

    printf("arg5='%08x/%d'\n", arg5->ipaddr4.u.addr32, arg5->prefix);

    ret = 0;
    fprintf(stdout, "OK");

    app_param_destroy(arg0);
    app_param_destroy(arg1);
    app_param_destroy(arg2);
    app_param_destroy(arg3);
    app_param_destroy(arg4);
    app_param_destroy(arg5);
    return ret;
}

int main(int argc, char** argv)
{
    int ret;

    app_t *app = app_create("democmd",
            PRJ_VERSION,
            PRJ_COPYRIGHT,
            "zhouxy<zhouxy314@163.com>,"
            "liaoxf<liaofei1128@163.com>",
            "democmd is a program to show how to use libcmd."
            );

    app_add_ptype(app, "date", sizeof(var_date_t), (ptype_parser_t) parse_date, "a date in format yyyy/mm/dd or yyyy-mm-dd");

    app_add_option(app, '0', "arg0", "int", 0, "arg0 with an int value");
    app_add_option(app, '1', "arg1", "string", 0, "arg1 with a string value");
    app_add_option(app, '2', "arg2", "ipaddr4", 0, "arg2 with an ipaddr4 value");
    app_add_option(app, '3', "arg3", NULL, 0, "arg3 with none value");
    app_add_option(app, '4', "arg4", "ethaddr", 1, "arg4 with ethaddr value repeatable");
    app_add_option(app, '5', "arg5", "cidraddr4", 0, "arg5 with cidraddr4 value");
    app_add_option(app, '6', "arg6", "ipaddr6", 0, "arg6 with ipaddr6 value");
    app_add_option(app, '7', "arg7", "time", 0, "arg7 with time value");
    app_add_option(app, '8', "arg8", "date", 0, "arg8 with date value");
    app_add_option(app, '9', "arg9", "range", 0, "arg9 with range value");
    app_add_option(app, -1, "argx", "uint16", 0, "argx with unsigned 16 bits integer value");

    app_add_option(app, 'C', "process", NULL, 0, "process option to action");

    app_add_cmdline(app, "process,arg0,arg1,[arg2,arg3,arg4],arg5", do_process, "process something with a lot of arguments.");

    ret = app_run(app, argc, argv);

    app_destroy(app);
    return ret;
}

