/**
 * @file keyinfo.c
 * @author basilguo@163.com
 * @brief
 * @version 0.0.1
 * @date 2024-09-14
 *
 * @copyright Copyright (c) 2021 - 2024
 */

#ifdef __cplusplus
extern "C"
{
#endif /* __cplusplus */

#include "fcserver.h"
#include "libdiag.h"
#include <stdio.h>
#include <stdlib.h>

    int fc_server_pubkey_handler(int clisockfd, const unsigned char *buff, int len)
    {
        DIAG_INFO("TODO pubkey\n");
        return 0;
    }

#ifdef __cplusplus
}
#endif /* __cplusplus */
