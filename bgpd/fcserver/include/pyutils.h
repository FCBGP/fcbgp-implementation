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

typedef struct py_config_st
{
    PyObject *manager;
    PyObject *connect_ssh;
} py_confit_t;

#endif // PYUTILS_H
