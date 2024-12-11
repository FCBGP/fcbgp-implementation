#ifndef LIBCMD_H
#define LIBCMD_H

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef void app_t;
typedef void ptype_t;
typedef void param_t;
typedef void option_t;
typedef void cmdline_t;

typedef int (*ptype_parser_t)(char*, param_t*);
typedef int (*cmdline_handler_t)(app_t*, cmdline_t*);

/* libcmd.c */
extern int app_add_ptype(app_t* app, char* name, int size,
                         ptype_parser_t parser, char* desc);
extern int app_add_option(app_t* app, char opt, char* name, char* ptype,
                          char repeatable, char* desc);
extern void app_param_destroy(param_t* param);
extern param_t* app_param_get(app_t* app, char* name);
extern int app_param_array(app_t* app, char* name, param_t*** paramarray);
extern int app_parse_input(char* prompt, ptype_parser_t parser,
                           param_t** pparam, int sizeofparam);
extern int app_add_cmdline(app_t* app, char* options, cmdline_handler_t handler,
                           char* desc);
extern app_t* app_create(char* name, char* version, char* copyright,
                         char* authors, char* desc);
extern void app_destroy(app_t* app);
extern void app_priv_set(app_t* app, void* priv);
extern void* app_priv_get(app_t* app);

extern int app_version(app_t* app, cmdline_t* cmdline);
extern int app_help(app_t* app, cmdline_t* cmdline);
extern int app_usage(app_t* app, cmdline_t* cmdline);
extern int app_daemonize(app_t* app, cmdline_t* cmdline);

extern int app_run(app_t* app, int argc, char* argv[]);

#endif
