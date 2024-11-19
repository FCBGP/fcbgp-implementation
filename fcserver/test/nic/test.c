
#include <stdio.h>
#include <unistd.h>

#include "ifinfo.h"


void ifdisplay(const struct ifinfo *info, void *arg)
{
    printf("%2d: %-10s %16s %18s %d Mb \n",
            info->if_idx, info->if_name,info->if_ipv4, info->if_eth.if_ethmac,info->if_eth.if_ethspeed);
}


int main()
{
    int ret = 0;
    while(1) {
        ret = get_ifinfo(ifdisplay, NULL);
        printf("Total %d interface.\n", ret);
        sleep(1);
    }
}

