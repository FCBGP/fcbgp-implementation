#include "libcmd.h"
#include "liblist.h"
#include "libstring.h"

#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

struct ptype_st {
    char *name;
    char *description;
    int size;
    int refcnt;
    ptype_parser_t parser;
};

#define OPT_ISNONE(opt) (((opt) & 0xFF) == 0xFF)

struct option_st {
    char opt;
    char *name;
    char *description;
    struct ptype_st *pptype;
    int parsed:1;
    int repeatable:1;
    slist_t params;
};

struct cmdline_st {
    char *description;
    slist_t *mandatory;
    slist_t *dispensable;
    cmdline_handler_t handler;
};

struct app_st {
    char *name;
    char *version;
    char *authors;
    char *copyright;
    char *description;

    int max_ptype_name;
    int max_option_name;

    slist_t ptypes;
    slist_t options;
    slist_t cmdlines;

    void *priv;
};

struct cbdata_st {
    app_t *app;
    slist_t *mandatory;
    slist_t *dispensable;
    char *input;
};

/*
 *ptype API
 */

static ptype_t *ptype_create(char *name, int size, ptype_parser_t parser, char *desc)
{
    struct ptype_st *pptype;

    pptype = malloc(sizeof(*pptype));
    if (pptype == NULL) {
        return NULL;
    }

    pptype->name = name;
    pptype->size = size;
    pptype->parser = parser;
    pptype->description = desc;
    pptype->refcnt = 0;

    return pptype;
}

static void ptype_destroy(ptype_t * ptype)
{
    free(ptype);
}

static int ptype_compare_by_name(ptype_t * ptype, void *key)
{
    char *name = key;
    struct ptype_st *pptype = ptype;

    return strcmp(pptype->name, name);
}

static ptype_t *app_find_ptype_by_name(app_t * app, char *name)
{
    struct app_st *papp = app;

    return slist_search(&papp->ptypes, (void *) name, ptype_compare_by_name);
}

static int app_link_ptype(app_t * app, ptype_t * ptype)
{
    struct app_st *papp = app;
    struct ptype_st *pptype = ptype;
    int ptype_name_len = strlen(pptype->name);

    if (papp->max_ptype_name < ptype_name_len)
        papp->max_ptype_name = ptype_name_len;

    return slist_add_tail(&papp->ptypes, ptype);
}

int app_add_ptype(app_t * app, char *name, int size, ptype_parser_t parser, char *desc)
{
    ptype_t *ptype;

    ptype = app_find_ptype_by_name(app, name);
    if (ptype) {
        fprintf(stderr, "ptype %s does exist!\n", name);
        return -1;
    }

    ptype = ptype_create(name, size, parser, desc);
    if (ptype == NULL) {
        fprintf(stderr, "ptype %s create failed!\n", name);
        return -1;
    }

    return app_link_ptype(app, ptype);
}

/*
 *option API
 */

static option_t *option_create(char opt, char *name, ptype_t * ptype, char repeatable, char *desc)
{
    struct option_st *poption;

    poption = malloc(sizeof(*poption));
    if (poption == NULL) {
        return NULL;
    }

    poption->opt = opt;
    poption->name = name;
    poption->description = desc;
    poption->pptype = ptype;
    poption->parsed = 0;
    poption->repeatable = repeatable;
    slist_init(&poption->params);
    return poption;
}

static void option_destroy(option_t * option)
{
    struct option_st *poption = option;

    if (poption) {
        slist_fini(&poption->params, app_param_destroy);
        free(poption);
    }
}

static int option_compare_by_opt(option_t * option, void *key)
{
    char *opt = (char *) key;
    struct option_st *poption = option;

    return (poption->opt != *opt);
}

static option_t *app_find_option_by_opt(app_t * app, char opt)
{
    struct app_st *papp = app;

    if (OPT_ISNONE(opt)) {
        return NULL;
    }

    return slist_search(&papp->options, (void *) &opt, option_compare_by_opt);
}

static int option_compare_by_name(option_t * option, void *key)
{
    char *name = (char *) key;
    struct option_st *poption = option;

    return strcmp(poption->name, name);
}

static option_t *app_find_option_by_name(app_t * app, char *name)
{
    struct app_st *papp = app;

    return slist_search(&papp->options, (void *) name, option_compare_by_name);
}

static int app_link_option(app_t * app, option_t * option)
{
    struct app_st *papp = app;
    struct option_st *poption = option;
    int option_name_len = strlen(poption->name);

    if (papp->max_option_name < option_name_len)
        papp->max_option_name = option_name_len;

    return slist_add_tail(&papp->options, option);
}

int app_add_option(app_t * app, char opt, char *name, char *ptype, char repeatable, char *desc)
{
    option_t *option;
    struct ptype_st *pptype = NULL;

    if (ptype) {
        pptype = app_find_ptype_by_name(app, ptype);
        if (pptype == NULL) {
            fprintf(stderr, "ptype %s does not exist!\n", ptype);
            return -1;
        }
    }

    option = app_find_option_by_opt(app, opt);
    if (option) {
        fprintf(stderr, "option %c does exist!\n", opt);
        return -1;
    }

    option = app_find_option_by_name(app, name);
    if (option) {
        fprintf(stderr, "option %s does exist!\n", name);
        return -1;
    }

    option = option_create(opt, name, pptype, repeatable, desc);
    if (option == NULL) {
        fprintf(stderr, "option %s create failed!\n", name);
        return -1;
    }

    if (pptype) {
        pptype->refcnt++;
    }

    return app_link_option(app, option);
}

/*
 *param API
 */
static param_t *app_param_create(int size)
{
    param_t *param;

    param = malloc(size);
    if (param == NULL) {
        return NULL;
    }

    memset(param, 0, size);
    return param;
}

void app_param_destroy(param_t * param)
{
    if (param) {
        free(param);
    }
}

static int app_param_parse(char *arg, option_t * option)
{
    int ret = -1;
    param_t *param = NULL;
    struct option_st *poption = option;

    if (poption->pptype) {
        param = app_param_create(poption->pptype->size);
        if (param == NULL) {
            return ret;
        }

        ret = (poption->pptype->parser) (arg, param);
        if (ret < 0) {
            app_param_destroy(param);
            return ret;
        }
    } else {
        param = app_param_create(sizeof(var_boolean_t));
        if (param == NULL) {
            return ret;
        }

        ret = parse_boolean(arg, param);
        if (ret < 0) {
            app_param_destroy(param);
            return ret;
        }
    }

    ret = slist_add_tail(&poption->params, param);
    if (ret < 0) {
        app_param_destroy(param);
        return ret;
    }

    return ret;
}

param_t *app_param_get(app_t * app, char *name)
{
    param_t *param = NULL;
    struct option_st *poption = app_find_option_by_name(app, name);

    if (poption && slist_del(&poption->params, &param)) {
        return param;
    } else {
        return NULL;
    }
}

int app_param_array(app_t * app, char *name, param_t *** paramarray)
{
    struct option_st *poption = app_find_option_by_name(app, name);

    return slist_array(&poption->params, paramarray);
}

int app_parse_input(char *prompt, ptype_parser_t parser, param_t **pparam, int sizeofparam)
{
    int ret = -1;
    param_t *param = NULL;
    char line[1024] = {0, };

    if (parser == NULL) {
        fprintf(stderr, "invalid parser handler.\n");
        return -1;
    }

    param = malloc(sizeofparam);
    if (param == NULL) {
        fprintf(stderr, "alloc parameter failed.\n");
        return -1;
    }

    while (1) {
        fprintf(stdout, "%s", prompt);
        if (fgets(line, sizeof(line), stdin) == NULL) {
            fprintf(stdout, "\n");
            continue;
        }

        ret = strlen(line);
        if (line[ret - 1] == '\n') line[ret - 1] = '\0';

        memset(param, 0, sizeofparam);
        ret = parser(line, param);
        if (ret < 0) {
            fprintf(stderr, "invalid input line.\n");
            continue;
        }

        break;
    }

    *pparam = param;
    return 0;
}

/*
 *cmdline API
 */

static cmdline_t *cmdline_create(slist_t * mandatory, slist_t * dispensable, cmdline_handler_t handler, char *desc)
{
    struct cmdline_st *pcmdline;

    pcmdline = malloc(sizeof(*pcmdline));
    if (pcmdline == NULL) {
        return NULL;
    }

    pcmdline->mandatory = mandatory;
    pcmdline->dispensable = dispensable;
    pcmdline->description = desc;
    pcmdline->handler = handler;

    return pcmdline;
}

static void cmdline_destroy(cmdline_t * cmdline)
{
    struct cmdline_st *pcmdline = cmdline;

    if (pcmdline) {
        slist_fini(pcmdline->mandatory, NULL);
        free(pcmdline->mandatory);
        slist_fini(pcmdline->dispensable, NULL);
        free(pcmdline->dispensable);
        free(pcmdline);
    }
}

static int cmdline_options_match(slist_t * mandatory, slist_t * dispensable, slist_t * options)
{
    slist_node_t *p;

    if (mandatory) {
        for (p = mandatory->head; p; p = p->next) {
            if (!slist_search(options, p->value, NULL)) {
                return 0;
            }
        }
    }

    for (p = options->head; p; p = p->next) {
        if (!slist_search(mandatory, p->value, NULL)
            && !slist_search(dispensable, p->value, NULL)) {
            return 0;
        }
    }

    return 1;
}

static int cmdline_compare(cmdline_t * cmdline, void *key)
{
    struct cmdline_st *pcmdline = cmdline;
    struct cbdata_st *pcbdata = key;

    if (pcbdata->mandatory == NULL || slist_empty(pcbdata->mandatory)) {
        if (!pcmdline->mandatory) {
            return 0;
        }
    } else {
        if (cmdline_options_match(pcmdline->mandatory, pcmdline->dispensable, pcbdata->mandatory)) {
            return 0;
        }
    }

    return -1;
}

static int cmdline_options_repeat(slist_t * mandatory1, slist_t * dispensable1, slist_t * mandatory2, slist_t * dispensable2)
{
    slist_node_t *p;
    slist_t diff1, diff2;

    slist_init(&diff1);
    slist_init(&diff2);

    if (mandatory1) {
        for (p = mandatory1->head; p; p = p->next) {
            if (!slist_search(mandatory2, p->value, NULL)) {
                slist_add_tail(&diff1, p->value);
            }
        }
    }

    if (mandatory2) {
        for (p = mandatory2->head; p; p = p->next) {
            if (!slist_search(mandatory1, p->value, NULL)) {
                slist_add_tail(&diff2, p->value);
            }
        }
    }

    if (slist_subset(dispensable2, &diff1, NULL)
        && slist_subset(dispensable1, &diff2, NULL)) {
        slist_fini(&diff1, NULL);
        slist_fini(&diff2, NULL);
        return 1;
    }

    slist_fini(&diff1, NULL);
    slist_fini(&diff2, NULL);
    return 0;
}

static int cmdline_repeat(cmdline_t * cmdline, void *key)
{
    int ret = -1;
    struct cmdline_st *pcmdline = cmdline;
    struct cbdata_st *pcbdata = key;

    if (cmdline_options_repeat(pcmdline->mandatory, pcmdline->dispensable, pcbdata->mandatory, pcbdata->dispensable)) {
        ret = 0;
    }

    return ret;
}

static cmdline_t *app_find_cmdline(app_t * app, slist_t * mandatory, slist_t * dispensable, int (*cmdline_compare) (cmdline_t * cmdline, void *key))
{
    struct app_st *papp = app;
    struct cbdata_st cbdata;

    cbdata.mandatory = mandatory;
    cbdata.dispensable = dispensable;

    return slist_search(&papp->cmdlines, &cbdata, cmdline_compare);
}

static int app_link_cmdline(app_t * app, cmdline_t * cmdline)
{
    struct app_st *papp = app;

    return slist_add_tail(&papp->cmdlines, cmdline);
}

/*
 *get the sorted mandatory and dispensable options
 */
static int cmdline_options_parse(app_t * app, char *options, slist_t ** pmandatory, slist_t ** pdispensable)
{
    int vi = 1, next_vi;
    option_t *option;
    char *p, *q, *name = NULL;

    slist_t *mandatory = NULL;
    slist_t *dispensable = NULL;

    if (options == NULL) {
        goto done;
    }

    /*
     * "option1,option2,option3,[option4,option5],option6"
     */
    p = options;
    while (*p) {
        if (*p == '[') {
            vi = 0;
            p++;
            continue;
        }

        if (*p == ']') {
            vi = 1;
            p++;
            continue;
        }

        next_vi = vi;
        q = strchr(p, ',');
        if (q) {
            name = strndup(p, q - p);
            p = q + 1;
            q = strchr(name, ']');  // close bracket
            if (q) {
                next_vi = 1;
                *q = '\0';
            }
        } else {
            q = strchr(p, ']'); // close bracket.
            if (q) {
                name = strndup(p, q - p);
                next_vi = 1;
                p = q + 1;
            } else {
                name = strdup(p);
                p = NULL;
            }
        }

        option = app_find_option_by_name(app, name);
        if (option == NULL) {
            fprintf(stderr, "option %s does not exist!\n", name);
            free(name);
            goto out;
        }

        if (vi) {
            if (mandatory == NULL) {
                mandatory = malloc(sizeof(slist_t));
                if (mandatory == NULL) {
                    free(name);
                    goto out;
                }
                slist_init(mandatory);
            }
            if (dispensable) {
                if (slist_search(dispensable, option, NULL)) {
                    fprintf(stderr, "option %s repeat!\n", name);
                    free(name);
                    goto out;
                }
            }
            slist_add_tail_exclusive(mandatory, option, NULL);
        } else {
            if (dispensable == NULL) {
                dispensable = malloc(sizeof(slist_t));
                if (dispensable == NULL) {
                    free(name);
                    goto out;
                }
                slist_init(dispensable);
            }
            if (mandatory) {
                if (slist_search(mandatory, option, NULL)) {
                    fprintf(stderr, "option %s repeat!\n", name);
                    free(name);
                    goto out;
                }
            }
            slist_add_tail_exclusive(dispensable, option, NULL);
        }

        free(name);
        vi = next_vi;
        if (p == NULL)
            break;
    }

done:
    *pmandatory = mandatory;
    *pdispensable = dispensable;
    return 0;
out:
    slist_fini(mandatory, NULL);
    free(mandatory);
    slist_fini(dispensable, NULL);
    free(dispensable);
    return -1;
}

int app_add_cmdline(app_t * app, char *options, cmdline_handler_t handler, char *desc)
{
    cmdline_t *cmdline;

    slist_t *mandatory = NULL;
    slist_t *dispensable = NULL;

    if (cmdline_options_parse(app, options, &mandatory, &dispensable)) {
        fprintf(stderr, "invalid options for command line %s!\n", options);
        return -1;
    }

    cmdline = app_find_cmdline(app, mandatory, dispensable, cmdline_repeat);
    if (cmdline) {
        fprintf(stderr, "cmdline %s repeat!\n", options);
        goto errout;
    }

    cmdline = cmdline_create(mandatory, dispensable, handler, desc);
    if (cmdline == NULL) {
        fprintf(stderr, "alloc cmdline failed!\n");
        goto errout;
    }

    return app_link_cmdline(app, cmdline);
errout:
    slist_fini(mandatory, NULL);
    free(mandatory);
    slist_fini(dispensable, NULL);
    free(dispensable);
    return -1;
}

/*
 *app helper API
 */
int app_version(app_t * app, cmdline_t * cmdline)
{
    char *p = NULL;
    char *q = NULL;
    char author[128] = {0, };
    struct app_st *papp = app;
    int appnamelen = strlen(papp->name);

    fprintf(stdout, "%s - %s\n", papp->name, papp->description);
    fprintf(stdout, "%*c %s Compiled %s %s\n", appnamelen + 2, ' ', papp->version, __DATE__, __TIME__);
    fprintf(stdout, "%*c %s\n", appnamelen + 2, ' ', papp->copyright);

    q = papp->authors;
    while (1) {
        p = strchr(q, ',');
        if (p == NULL) {
            fprintf(stdout, "%*c %s\n", appnamelen + 2, ' ', q);
            break;
        }
        memcpy(author, q, p - q);
        author[p - q] = '\0';
        fprintf(stdout, "%*c %s\n", appnamelen + 2, ' ', author);
        q = p + 1;
    }

    fprintf(stdout, "\n");

    fprintf(stderr, "Try `help' for more information.\n");
    return 0;
}

static int ptype_dump(ptype_t * ptype, void *arg, int arg_len)
{
    struct cbdata_st *pcbdata = arg;
    struct ptype_st *pptype = ptype;
    struct app_st *papp = pcbdata->app;
    int maxlen = papp->max_ptype_name;
    int ptypenamelen = strlen(pptype->name);

    if (!pptype->refcnt)
        return 0;

    fprintf(stdout, YELLOWFMT("%s") "%*c%s\n", pptype->name, maxlen - ptypenamelen + 1, ' ', pptype->description);
    return 0;
}

static int option_dump(option_t * option, void *arg, int arg_len)
{
    struct cbdata_st *pcbdata = arg;
    struct option_st *poption = option;
    struct app_st *papp = pcbdata->app;
    int maxlen = papp->max_ptype_name + papp->max_option_name;
    int optnamelen = strlen(poption->name);
    int ptypenamelen = (poption->pptype == NULL) ? 0 : strlen(poption->pptype->name);

    if (pcbdata->input) {
        if (strprefixcmp(poption->name, pcbdata->input)) {
            return 0;
        }
    }

    if (poption->pptype) {
        if (poption->repeatable) {
            fprintf(stdout, MAGENTAFMT("%s") " {" YELLOWFMT("%s") "}%*c%c%c %s(repeatable)\n",
                    poption->name, poption->pptype->name,
                    maxlen - optnamelen - ptypenamelen + 1, ' ',
                    isprint((int)poption->opt) ? '-' : ' ', isprint((int)poption->opt) ? poption->opt : ' ', poption->description);
        } else {
            fprintf(stdout, MAGENTAFMT("%s") " {" YELLOWFMT("%s") "}%*c%c%c %s\n",
                    poption->name, poption->pptype->name,
                    maxlen - optnamelen - ptypenamelen + 1, ' ',
                    isprint((int)poption->opt) ? '-' : ' ', isprint((int)poption->opt) ? poption->opt : ' ', poption->description);
        }
    } else {
        fprintf(stdout, MAGENTAFMT("%s") "%*c%c%c %s\n",
                poption->name, maxlen - optnamelen + 4, ' ', isprint((int)poption->opt) ? '-' : ' ', isprint((int)poption->opt) ? poption->opt : ' ', poption->description);
    }

    return 0;
}

int app_help(app_t * app, cmdline_t * cmdline)
{
    struct app_st *papp = app;
    struct cbdata_st cbdata = { app, };

    fprintf(stdout, "All options registered in this application:\n");
    slist_foreach(&papp->options, option_dump, &cbdata, sizeof(cbdata));
    fprintf(stdout, "\n");

    fprintf(stdout, "All parameters registered in this application:\n");
    slist_foreach(&papp->ptypes, ptype_dump, &cbdata, sizeof(cbdata));
    fprintf(stdout, "\n");
    return 0;
}

static int cmdline_accept_option(cmdline_t * cmdline, char *option)
{
    slist_node_t *p;
    struct option_st *poption;
    struct cmdline_st *pcmdline = cmdline;

    p = pcmdline->mandatory ? pcmdline->mandatory->head : NULL;
    for (; p; p = p->next) {
        poption = p->value;
        if (!strcmp(option, poption->name)) {
            return 1;
        }
    }

    p = pcmdline->dispensable ? pcmdline->dispensable->head : NULL;
    for (; p; p = p->next) {
        poption = p->value;
        if (!strcmp(option, poption->name)) {
            return 1;
        }
    }

    return 0;
}

static int cmdline_dump(cmdline_t * cmdline, void *arg, int arg_len)
{
    int len;
    int termw = 200;

    slist_node_t *p;
    struct option_st *poption;
    struct cmdline_st *pcmdline = cmdline;
    struct cbdata_st *cbdata = (struct cbdata_st *)arg;

    if (cbdata->input) {
        if (!cmdline_accept_option(cmdline, cbdata->input))
            return 0;
    }

    len = 0;
    p = pcmdline->mandatory ? pcmdline->mandatory->head : NULL;
    for (; p; p = p->next) {
        if (len > termw && p->next) {
            fprintf(stdout, "\n%*c", 4, ' ');
            len = 0;
        }

        poption = p->value;
        if (poption->pptype) {
            len += fprintf(stdout, MAGENTAFMT("%s") " {" YELLOWFMT("%s") "} ", poption->name, poption->pptype->name);
        } else {
            len += fprintf(stdout, MAGENTAFMT("%s") " ", poption->name);
        }
    }

    p = pcmdline->dispensable ? pcmdline->dispensable->head : NULL;
    for (; p; p = p->next) {
        if (len > termw && p->next) {
            fprintf(stdout, "\n%*c", 4, ' ');
            len = 0;
        }

        poption = p->value;
        if (poption->pptype) {
            len += fprintf(stdout, "[" MAGENTAFMT("%s") " {" YELLOWFMT("%s") "}] ", poption->name, poption->pptype->name);
        } else {
            len += fprintf(stdout, "[" MAGENTAFMT("%s") "] ", poption->name);
        }
    }

    fprintf(stdout, "\n%*c", 4, ' ');
    fprintf(stdout, "%s", pcmdline->description);
    fprintf(stdout, "\n");

    return 0;
}

int app_usage(app_t * app, cmdline_t * cmdline)
{
    struct app_st *papp = app;
    struct cbdata_st cbdata = { app, };

    fprintf(stdout, "All command lines registered in this application:\n");
    slist_foreach(&papp->cmdlines, cmdline_dump, &cbdata, sizeof(cbdata));

    return 0;
}

int app_daemonize(app_t * app, cmdline_t * cmdline)
{
    pid_t pid, sid;

    /* already a daemon */
    if (getppid() == 1)
        return 1;

    /* fork off the parent process */
    pid = fork();
    if (pid < 0) {
        exit(EXIT_FAILURE);
    }

    /* if we got a good PID, then we can exit the parent process. */
    if (pid > 0) {
        exit(EXIT_SUCCESS);
    }

    /* waiting for the parent process exiting.*/
    usleep(1000);

    /* at this point we are executing as the children process. */

    /* change the file mode mask */
    umask(0);

    /* create a new SID for the child process. */
    sid = setsid();
    if (sid < 0) {
        exit(EXIT_FAILURE);
    }

    /* change the current working directory.
     * This prevents the current directory from being locked;
     * hence not being able to remove it.
     */
    if (chdir("/") < 0) {
        exit(EXIT_FAILURE);
    }

    return 1;
}

/*
 *application API
 */

app_t *app_create(char *name, char *version, char *copyright, char *authors, char *desc)
{
    struct app_st *papp;

    papp = malloc(sizeof(*papp));
    if (papp == NULL) {
        return NULL;
    }

    papp->name = name;
    papp->version = version;
    papp->authors = authors;
    papp->copyright = copyright;
    papp->description = desc;

    papp->max_ptype_name = 0;
    papp->max_option_name = 0;

    slist_init(&papp->ptypes);
    slist_init(&papp->options);
    slist_init(&papp->cmdlines);

    app_add_ptype(papp, "int", sizeof(var_int_t), (ptype_parser_t) parse_int, "a 32 bits signed integer");
    app_add_ptype(papp, "uint", sizeof(var_uint_t), (ptype_parser_t) parse_uint, "a 32 bits unsigned integer");
    app_add_ptype(papp, "uint64", sizeof(var_uint64_t), (ptype_parser_t) parse_u64, "a 64 bits unsigned integer");
    app_add_ptype(papp, "uint32", sizeof(var_uint32_t), (ptype_parser_t) parse_uint, "a 32 bits unsigned integer");
    app_add_ptype(papp, "uint16", sizeof(var_uint16_t), (ptype_parser_t) parse_u16, "a 16 bits unsigned integer");
    app_add_ptype(papp, "uint8", sizeof(var_uint8_t), (ptype_parser_t) parse_u8, "a 8 bits unsigned integer");
    app_add_ptype(papp, "time", sizeof(var_time_t), (ptype_parser_t) parse_time, "a timestamp in format hh:mm:ss");
    app_add_ptype(papp, "datetime", sizeof(var_datetime_t), (ptype_parser_t) parse_datetime, "a datetime in format yyyy-mm-dd hh:mm:ss");
    app_add_ptype(papp, "boolean", sizeof(var_boolean_t), (ptype_parser_t) parse_boolean, "a boolean string like as yes/true/1 or no/false/0");
    app_add_ptype(papp, "string", sizeof(var_string_t), (ptype_parser_t) parse_string, "a string is something like a string");
    app_add_ptype(papp, "strbuf", sizeof(var_strbuf_t), (ptype_parser_t) parse_strbuf, "a string buffer is something like a string with max length 1024");
    app_add_ptype(papp, "float", sizeof(var_float_t), (ptype_parser_t) parse_float, "an IEEE 754 standard for floating-point numbers in 32 bits");
    app_add_ptype(papp, "double", sizeof(var_double_t), (ptype_parser_t) parse_double, "an IEEE 754 standard for floating-point numbers in 64 bits");
    app_add_ptype(papp, "complex", sizeof(var_complex_t), (ptype_parser_t) parse_complex, "a complex number in format a+bi");
    app_add_ptype(papp, "range", sizeof(var_range_t), (ptype_parser_t) parse_range, "a range in format a-b");
    app_add_ptype(papp, "ethaddr", sizeof(var_ethaddr_t), (ptype_parser_t) parse_ethaddr, "a valid MAC address in format HH:HH:HH:HH:HH:HH");
    app_add_ptype(papp, "ipaddr4", sizeof(var_ipaddr4_t), (ptype_parser_t) parse_ipaddr4, "a valid IPv4 address in format ddd.ddd.ddd.ddd");
    app_add_ptype(papp, "cidraddr4", sizeof(var_cidraddr4_t), (ptype_parser_t) parse_cidraddr4, "a valid IPv4 CIDR address, such as 192.168.1.1/24");
    app_add_ptype(papp, "ipaddr6", sizeof(var_ipaddr6_t), (ptype_parser_t) parse_ipaddr6, "a valid IPv6 address");
    app_add_ptype(papp, "cidraddr6", sizeof(var_cidraddr6_t), (ptype_parser_t) parse_cidraddr6, "a valid IPv6 CIDR address");
    app_add_ptype(papp, "mint", sizeof(var_multi_int_t), (ptype_parser_t) parse_multi_int, "multiple integer numbers in format i,i,i,...");
    app_add_ptype(papp, "muint", sizeof(var_multi_uint_t), (ptype_parser_t) parse_multi_uint, "multiple unsigned integer numbers in format u,u,u,...");
    app_add_ptype(papp, "mfloat", sizeof(var_multi_float_t), (ptype_parser_t) parse_multi_float, "multiple float numbers in format f,f,f,...");
    app_add_ptype(papp, "mdouble", sizeof(var_multi_double_t), (ptype_parser_t) parse_multi_double, "multiple double numbers in format d,d,d,...");
    app_add_ptype(papp, "mrange", sizeof(var_multi_range_t), (ptype_parser_t) parse_multi_range, "multiple range numbers in format i-i,i,i-i,...");

    app_add_option(papp, 'H', "help", NULL, 0, "show the help list");
    app_add_option(papp, 'U', "usage", NULL, 0, "show the detail usage list");
    app_add_option(papp, 'V', "version", NULL, 0, "show the application version");

    app_add_cmdline(papp, "help", app_help, "show the help list");
    app_add_cmdline(papp, "usage", app_usage, "show the detail usage list");
    app_add_cmdline(papp, "version", app_version, "show the application version");

    return papp;
}

void app_destroy(app_t * app)
{
    struct app_st *papp = app;

    if (papp) {
        slist_fini(&papp->ptypes, ptype_destroy);
        slist_fini(&papp->options, option_destroy);
        slist_fini(&papp->cmdlines, cmdline_destroy);
        free(papp);
    }
}

void app_priv_set(app_t * app, void *priv)
{
    struct app_st *papp = app;

    papp->priv = priv;

    return;
}

void *app_priv_get(app_t * app)
{
    struct app_st *papp = app;

    return papp->priv;
}

static int app_flush_option(option_t * option, void *arg, int arg_len)
{
    struct option_st *poption = option;

    if (poption->parsed) {
        slist_fini(&poption->params, app_param_destroy);
        poption->parsed = 0;
    }

    return 0;
}

static int app_help_option(option_t * option, void * arg, int arg_len)
{
    struct app_st *papp = arg;
    struct option_st *poption = option;
    struct cbdata_st cbdata = { papp, };

    cbdata.input = poption->name;

    if (OPT_ISNONE(poption->opt)) {
        fprintf(stdout, "Usage for option %s:\n", poption->name);
    } else {
        fprintf(stdout, "Usage for option %s(-%c):\n", poption->name, poption->opt);
    }

    slist_foreach(&papp->cmdlines, cmdline_dump, &cbdata, sizeof(cbdata));

    return 0;
}

static int app_match_option(app_t * app, char *input)
{
    struct app_st *papp = app;
    struct cbdata_st cbdata;

    cbdata.app = app;
    cbdata.input = input;

    slist_foreach(&papp->options, option_dump, &cbdata, sizeof(cbdata));
    return 0;
}

static void app_flush(app_t * app)
{
    struct app_st *papp = app;

    slist_foreach(&papp->options, app_flush_option, NULL, 0);
}

int app_run(app_t * app, int argc, char *argv[])
{
    int i;
    int ret = -1;
    struct option_st *poption = NULL;
    struct cmdline_st *pcmdline = NULL;

    slist_t input_opts;

    slist_init(&input_opts);

    i = 1; /**skip the prog name */
    while (i < argc) {
        if (argv[i][0] == '-') {
            if (argv[i][1] == '-') {
                if (argv[i][2] != '\0') {
                    poption = app_find_option_by_name(app, argv[i] + 2);
                    if (poption == NULL) {
                        fprintf(stderr, "unknown option %s, all options matched as following:\n", argv[i] + 2);
                        app_match_option(app ,argv[i] + 2);
                        goto out;
                    }
                } else {
                    fprintf(stderr, "invalid option %s.\n", argv[i]);
                    goto out;
                }
            } else {
                if (argv[i][1] == '\0') {
                    fprintf(stderr, "invalid option %s.\n", argv[i]);
                    goto out;
                }

                if (argv[i][2] != '\0') {
                    fprintf(stderr, "unknown option %s.\n", argv[i]);
                    goto out;
                }

                poption = app_find_option_by_opt(app, argv[i][1]);
                if (poption == NULL) {
                    fprintf(stderr, "unknown option %s.\n", argv[i]);
                    goto out;
                }
            }
        } else {
            poption = app_find_option_by_name(app, argv[i]);
            if (poption == NULL) {
                fprintf(stderr, "unknown option %s, all options matched as following:\n", argv[i]);
                app_match_option(app ,argv[i]);
                goto out;
            }
        }

        if (poption->parsed) {
            if (poption->repeatable == 0) {
                fprintf(stderr, "repeat input option %s.\n", poption->name);
                goto out;
            }
        }

        i++;
        if (poption->pptype) {
            if (i >= argc) {
                fprintf(stderr, "missing argument for option %s.\n", poption->name);
                goto out;
            }

            if (app_param_parse(argv[i], poption) < 0) {
                fprintf(stderr, "invalid argument %s for option %s.\n", argv[i], poption->name);
                goto out;
            }
            i++;
        } else {
            if (app_param_parse("true", poption) < 0) {
                fprintf(stderr, "parse option %s failed!\n", poption->name);
                goto out;
            }
        }

        /*
         * for the repeatable options, only save it one time!
         */
        if (!poption->parsed) {
            slist_add_tail_exclusive(&input_opts, poption, NULL);
            poption->parsed = 1;
        }
    }

    if (slist_empty(&input_opts)) {
        app_version(app, NULL);
        goto out;
    }

    pcmdline = app_find_cmdline(app, &input_opts, NULL, cmdline_compare);
    if (pcmdline) {
        if (pcmdline->handler) {
            ret = pcmdline->handler(app, pcmdline);
        } else {
            fprintf(stderr, "cmdline handler is not set!\n");
        }
    } else {
        fprintf(stderr, "find cmdline failed!\n");
        slist_foreach(&input_opts, app_help_option, app, sizeof(void *));
    }

out:
    slist_fini(&input_opts, NULL);
    app_flush(app);
    return ret;
}

