/********************************************************************************
 * File Name:    pyutils.c
 * Author:       basilguo@163.com
 * Version:      0.0.1
 * Created Time: 2024-05-13 10:24:57
 * Description:
 *******************************************************************************/

#include "pyutils.h"
#include "defines.h"
#include <Python.h>
#include <stdio.h>
#include <stdlib.h>

#define PY_FUNC_CHECK(funcptr)                                                 \
    do                                                                         \
    {                                                                          \
        if (funcptr == NULL || !PyCallable_Check(funcptr))                     \
        {                                                                      \
            if (PyErr_Occurred())                                              \
            {                                                                  \
                PyErr_Print();                                                 \
                exit(EXIT_FAILURE);                                            \
            }                                                                  \
        }                                                                      \
    } while (0)

#define PY_OBJECT_CHECK(objptr)                                                \
    do                                                                         \
    {                                                                          \
        if (objptr == NULL)                                                    \
        {                                                                      \
            PyErr_Print();                                                     \
            exit(EXIT_FAILURE);                                                \
        }                                                                      \
    } while (0)

void py_setup(py_config_t* py_config, const char* script_name, const char* host,
              const char* username, const char* password, const u16 port)
{
    PyObject* setup_func = NULL;

    Py_Initialize();

    // 添加Python脚本所在的路径到sys.path
    PyRun_SimpleString("import os, sys");
    PyRun_SimpleString("sys.path.append('./')");
    PyRun_SimpleString("sys.path.append('/etc/frr/assets')");
    PyRun_SimpleString("print(os.getcwd())");
    py_config->module = PyImport_ImportModule(script_name);
    PY_OBJECT_CHECK(py_config->module);

    setup_func = PyObject_GetAttrString(py_config->module, "setup");
    PY_FUNC_CHECK(setup_func);

    py_config->session = PyObject_CallFunction(setup_func, "sssi", host,
                                               username, password, port);
    PY_OBJECT_CHECK(py_config->session);

    if (setup_func)
    {
        Py_DECREF(setup_func);
    }
}

void py_teardown(py_config_t* py_config)
{
    PyObject *teardown_func = NULL, *result = NULL;

    teardown_func = PyObject_GetAttrString(py_config->module, "teardown");

    result =
        PyObject_CallFunctionObjArgs(teardown_func, py_config->session, NULL);
    if (result == NULL)
    {
        PyErr_Print();
    }
    else
    {
        Py_DECREF(result);
    }

    if (teardown_func)
    {
        Py_DECREF(teardown_func);
    }

    if (py_config->session)
    {
        Py_DECREF(py_config->session);
    }

    if (py_config->module)
    {
        Py_DECREF(py_config->module);
    }

    Py_Finalize();
}

PyObject* py_run_func(py_config_t* py_config, const char* funcname)
{
    PyObject* print_capa_func = NULL;
    PyObject* result = NULL;

    print_capa_func = PyObject_GetAttrString(py_config->module, funcname);
    PY_FUNC_CHECK(print_capa_func);

    result =
        PyObject_CallFunctionObjArgs(print_capa_func, py_config->session, NULL);
    PY_OBJECT_CHECK(result);

    return result;
}

int py_apply_acl(py_config_t* py_config, const u32 group_index,
                 const u8 ipversion, const bool flag_withdraw,
                 const u16 rule_id, const char* srcip, const int srcprefixlen,
                 const char* dstip, const int dstprefixlen,
                 const u32 iface_index, const int direction)
{
    int group_type = 0;
    int action = 2; // action: 1 for deny, 2 for permit
    PyObject* h3c_acl_func = NULL;
    PyObject* result = NULL;
    char* operation = flag_withdraw ? "delete" : "merge";

    h3c_acl_func = PyObject_GetAttrString(py_config->module, "h3c_acl");
    PY_FUNC_CHECK(h3c_acl_func);

    if (ipversion == IPV4)
        group_type = 1;
    else if (ipversion == IPV6)
        group_type = 2;

    result = PyObject_CallFunction(
        h3c_acl_func, "Oiiisisiisi", py_config->session, group_type,
        group_index, rule_id, srcip, srcprefixlen, dstip, dstprefixlen, action,
        operation, iface_index, direction);
    // PY_OBJECT_CHECK(result);
    Py_DECREF(result);

    return 0;
}