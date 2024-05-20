/********************************************************************************
 * File Name:    pyutils.h
 * Author:       basilguo@163.com
 * Version:      0.0.1
 * Created Time: 2024-05-13 10:34:12
 * Description:
 *******************************************************************************/

#ifndef PYUTILS_H
#define PYUTILS_H

#include <Python.h>
#include "sysconfig.h"

typedef struct py_config_st
{
    PyObject *module; // the script file
    PyObject *session; // manager.connect
} py_config_t;

extern void py_setup(const char *script_name);
extern PyObject* py_run_func(const char *funcname);
extern int py_apply_acl(const u32 group_index,
        const char *srcip, const int srcprefixlen,
        const char *dstip, const int dstprefixlen,
        const u32 iface_index, const int direction);
extern void py_teardown();

#endif // PYUTILS_H
