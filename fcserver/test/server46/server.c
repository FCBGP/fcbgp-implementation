/********************************************************************************
 * File Name:    server.c
 * Author:       basilguo@163.com
 * Created Time: 2023-12-25 10:12:20
 * Description:
 ********************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include "libncs6.h"

int main(int argc, char *argv[])
{
    ncs6_ctx_t *fc_bgpd_ctx6;
    if ((fc_bgpd_ctx6 = ncs6_create("demo test", 23160)) == NULL)
    {
        printf("create bgpd ncs failed\n");
        exit(-ENOMEM);
    }

    ncs6_setup(fc_bgpd_ctx6, "::", 23160, NULL, 0);
    ncs6_timeout(fc_bgpd_ctx6, 10, -1);
    ncs6_setkeepalive(fc_bgpd_ctx6, 10);
    ncs6_server_enable(fc_bgpd_ctx6);
    ncs6_server_register(fc_bgpd_ctx6, NULL);
    ncs6_manager_start(fc_bgpd_ctx6);

    int i = 0;
    while (1)
    {
        sleep(10);
        printf("%04d\n", i);
    }

    ncs6_manager_stop(fc_bgpd_ctx6);

    return 0;
}
