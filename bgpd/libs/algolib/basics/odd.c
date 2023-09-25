/*************************************************************************
 * File Name:    odd.c
 * Author:       basilguo@163.com
 * Created Time: 2022-03-26 04:49:30
 * Description:
 ************************************************************************/

#include <stdio.h>
#include <stdlib.h>

int main(void)
{
    int x;
    scanf("%d", &x);

    if (x & 1)
    {
        printf("%d is odd\n", x);
    }
    else
    {
        printf("%d is even\n", x);
    }

    return 0;
}
