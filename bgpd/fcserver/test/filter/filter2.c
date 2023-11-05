/********************************************************************************
 * File Name:    filter2.c
 * Author:       basilguo@163.com
 * Created Time: 2023-10-25 04:04:51
 * Description:
 ********************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char *argv[])
{
    int ret = 0;
    const char *direction = "OUTPUT";
    const char *dstip = "192.168.88.132";
    const char *const program = "/usr/sbin/iptables";
    const char cmd[100] = {0};

    /*
    ret = execl(program, "iptables", "-t", "filter", "-A", direction,
            "-d", dstip, "-j", "DROP", NULL);
            */

    sprintf(cmd, "nft add rule filter INPUT iif ens36 "
            "ip saddr %s ip daddr %s drop",
            "100.0.0.0/8", "200.0.0.0/8");
    ret = system(cmd);
    printf("ret = %d\n", ret);


    return 0;
}
