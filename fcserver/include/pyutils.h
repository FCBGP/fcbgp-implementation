/********************************************************************************
 * File Name:    pyutils.h
 * Author:       basilguo@163.com
 * Version:      0.0.1
 * Created Time: 2024-05-13 10:34:12
 * Description:
 *******************************************************************************/

#ifndef PYUTILS_H
#define PYUTILS_H

#include "sysconfig.h"
#include <Python.h>
#include <stdbool.h>

typedef struct py_config_st
{
    PyObject* module;  // the script file
    PyObject* session; // manager.connect
} py_config_t;

extern void py_setup(py_config_t* py_config, const char* script_name,
                     const char* host, const char* username,
                     const char* password, const u16 port);
extern PyObject* py_run_func(py_config_t* py_config, const char* funcname);
extern int py_apply_acl(py_config_t* py_config, const u32 group_index,
                        const u8 ipversion, const bool flag_withdraw,
                        const u16 rule_id, const char* srcip,
                        const int srcprefixlen, const char* dstip,
                        const int dstprefixlen, const u32 iface_index,
                        const int direction);
extern void py_teardown(py_config_t* py_config);

#endif // PYUTILS_H
