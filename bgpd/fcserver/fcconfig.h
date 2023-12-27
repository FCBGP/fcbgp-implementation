/********************************************************************************
 * File Name:    fcconfig.h
 * Author:       basilguo@163.com
 * Created Time: 2023-12-19 08:55:22
 * Description:  local config
 ********************************************************************************/

#ifndef FCCONFIG_H
#define FCCONFIG_H

#include "defines.h"
#include "sigutils.h"

enum {
    FC_LOG_LEVEL_EMERG = 0,
    FC_LOG_LEVEL_ERROR = 1,
    FC_LOG_LEVEL_WARNING = 2,
    FC_LOG_LEVEL_INFO = 3,
    FC_LOG_LEVEL_DEBUG = 4,
    FC_LOG_LEVEL_VERBOSE = 5,
    FC_LOG_LEVEL_MAX
};

extern int fc_read_config(void);
extern int fc_set_log_mode(const char *mode_string);

#endif // FCCONFIG_H
