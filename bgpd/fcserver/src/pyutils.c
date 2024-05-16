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

py_config_t g_py_config = {0};

/* Load a symbol from a module */
PyObject *import_name(const char *modname, const char *symbol)
{
    PyObject *u_name, *module;
    u_name = PyUnicode_FromString(modname);
    module = PyImport_Import(u_name);
    Py_DECREF(u_name);
    return PyObject_GetAttrString(module, symbol);
}

    int
py_setup(char *host, int port, char *username, char *password)
{
    Py_Initialize();
    g_py_config.manager = import_name("ncclient", "manager");
    g_py_config.connect_ssh = import_name("manager", "connect_ssh");

}

    int
py_teardown()
{
    Py_Finalize();
}
