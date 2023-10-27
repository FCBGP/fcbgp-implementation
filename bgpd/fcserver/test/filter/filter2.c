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

    ret = execl(program, "iptables", "-t", "filter", "-A", direction,
            "-d", dstip, "-j", "DROP", NULL);
    printf("ret = %d\n", ret);


    return 0;
}
