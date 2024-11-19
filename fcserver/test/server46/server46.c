/********************************************************************************
 * File Name:    server46.c
 * Author:       basilguo@163.com
 * Created Time: 2023-12-25 08:46:18
 * Description:  For testing how to enable both ipv4 and ipv6.
 ********************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

int main(int argc, char *argv[])
{
    int sockfd = 0;
    int clntfd = 0;
    struct sockaddr_in6 serv_addr;
    struct sockaddr_in6 clnt_addr;

    serv_addr.sin6_family = AF_INET6;
    serv_addr.sin6_port = htons(23160);
    serv_addr.sin6_addr = in6addr_any;

    if ((sockfd = socket(AF_INET6, SOCK_STREAM, 0)) < 0)
    {
        perror("socket()");
        exit(EXIT_FAILURE);
    }

    int opt = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(int));
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(int));

    if (bind(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
        perror("bind()");
        exit(EXIT_FAILURE);
    }
    if (listen(sockfd, 5) < 0)
    {
        perror("listen()");
        exit(EXIT_FAILURE);
    }

    socklen_t clnt_len = sizeof(struct sockaddr);
    while ((clntfd = accept(sockfd, (struct sockaddr *)&clnt_addr,
                    &clnt_len)) > 0)
    {
        int  addrform;
        socklen_t len = sizeof(addrform);

        if (getsockopt(clntfd, IPPROTO_IPV6, IPV6_ADDRFORM,
                    (char *) &addrform, &len) == -1)
            perror("getsockopt IPV6_ADDRFORM");
        else if (addrform == PF_INET)
            printf("This is an IPv4 socket.\n");
        else if (addrform == PF_INET6)
        {
            printf("This is an IPv6 socket.\n");
            char addr[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &clnt_addr.sin6_addr,
                    addr, sizeof(struct sockaddr_in6));
            printf("addr: %s\n", addr);
        }
        else
            printf("This system is broken.\n");
        close(clntfd);
    }


    return 0;
}
