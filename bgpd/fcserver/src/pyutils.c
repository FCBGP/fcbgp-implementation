/********************************************************************************
 * File Name:    pyutils.c
 * Author:       basilguo@163.com
 * Version:      0.0.1
 * Created Time: 2024-05-13 10:24:57
 * Description:
 *******************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <Python.h>
#include "pyutils.h"

py_config_t g_py_config = {0};

#define PY_FUNC_CHECK(funcptr)                                  \
    do {                                                        \
        if (funcptr == NULL || !PyCallable_Check(funcptr)) {    \
            if (PyErr_Occurred()) {                             \
                PyErr_Print();                                  \
                exit(EXIT_FAILURE);                             \
            }                                                   \
        }                                                       \
    } while (0)

#define PY_OBJECT_CHECK(objptr)                                 \
    do {                                                        \
        if (objptr == NULL) {                                   \
            PyErr_Print();                                      \
            exit(EXIT_FAILURE);                                 \
        }                                                       \
    } while (0)

void py_setup(const char *script_name)
{
    PyObject *setup_func = NULL;

    Py_Initialize();

    // 添加Python脚本所在的路径到sys.path
    PyRun_SimpleString("import os, sys");
    PyRun_SimpleString("sys.path.append('./')");
    PyRun_SimpleString("sys.path.append('/etc/frr/assets')");
    PyRun_SimpleString("print(os.getcwd())");
    g_py_config.module = PyImport_ImportModule(script_name);
    PY_OBJECT_CHECK(g_py_config.module);

    setup_func = PyObject_GetAttrString(g_py_config.module, "setup");
    PY_FUNC_CHECK(setup_func);

    g_py_config.session = PyObject_CallObject(setup_func, NULL);
    PY_OBJECT_CHECK(g_py_config.session);

    if (setup_func)
    {
        Py_DECREF(setup_func);
    }
}

void py_teardown()
{
    PyObject *teardown_func = NULL, *result = NULL;

    teardown_func = PyObject_GetAttrString(g_py_config.module, "teardown");

    result = PyObject_CallFunctionObjArgs(teardown_func,
            g_py_config.session, NULL);
    if (result == NULL)
    {
        PyErr_Print();
    } else
    {
        Py_DECREF(result);
    }

    if (teardown_func)
    {
        Py_DECREF(teardown_func);
    }

    if (g_py_config.session)
    {
        Py_DECREF(g_py_config.session);
    }

    if (g_py_config.module)
    {
        Py_DECREF(g_py_config.module);
    }

    Py_Finalize();
}

PyObject *py_run_func(const char *funcname)
{
    PyObject *print_capa_func = NULL;
    PyObject* result = NULL;


    print_capa_func =
        PyObject_GetAttrString(g_py_config.module, funcname);
    PY_FUNC_CHECK(print_capa_func);

    result =
        PyObject_CallFunctionObjArgs(print_capa_func,
                g_py_config.session, NULL);
    PY_OBJECT_CHECK(result);

    return result;
}

int py_apply_acl(const u32 group_index,
        const char *srcip, const int srcprefixlen,
        const char *dstip, const int dstprefixlen,
        const u32 iface_index, const int direction)
{
    PyObject *acl_setup_func = NULL;
    PyObject *acl_rule_func = NULL;
    PyObject *acl_apply_func = NULL;
    PyObject *result = NULL;

    acl_setup_func = PyObject_GetAttrString(g_py_config.module, "acl_setup");
    PY_FUNC_CHECK(acl_setup_func);
    acl_rule_func = PyObject_GetAttrString(g_py_config.module, "acl_rule");
    PY_FUNC_CHECK(acl_rule_func);
    acl_apply_func = PyObject_GetAttrString(g_py_config.module, "acl_apply");
    PY_FUNC_CHECK(acl_apply_func);

    result = PyObject_CallFunction(acl_setup_func, "Oi",
            g_py_config.session, group_index);
    PY_OBJECT_CHECK(result);
    Py_DECREF(result);

    result = PyObject_CallFunction(acl_rule_func, "Osisi",
            g_py_config.session, group_index,
            srcip, srcprefixlen, dstip, dstprefixlen);
    PY_OBJECT_CHECK(result);
    Py_DECREF(result);

    result = PyObject_CallFunction(acl_apply_func, "Oiii",
            g_py_config, group_index, iface_index, direction);
    PY_OBJECT_CHECK(result);
    Py_DECREF(result);

    return 0;
}

#if 0
int main()
{
    py_setup("script");

    result = py_run_func("print_capabilities");
    if (result)
    {
        Py_DECREF(result);
    }

    py_teardown();

    return 0;
}
#endif
