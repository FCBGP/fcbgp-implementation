#ifndef _FOOREP_H_
#define _FOOREP_H_

#include "librep.h"

extern int foo_rep_init(void);
extern int foo_rep_register(dispatch_command_t* commands);
extern int foo_rep_start(void);
extern void foo_rep_loop(void);
extern void foo_rep_fini(void);
extern dispatch_command_t g_foo_commands[];

#endif
