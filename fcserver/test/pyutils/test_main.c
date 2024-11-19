#include "pyutils.h"

#if 0
int main()
{
    py_config_t py_config = {0};
    int result = 0;

    py_setup(&py_config, "script");

    result = py_run_func(&py_config, "print_capabilities");
    if (result)
    {
        Py_DECREF(result);
    }

    py_teardown(&py_config);

    return 0;
}
#endif