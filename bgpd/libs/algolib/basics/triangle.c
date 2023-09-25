/*************************************************************************
 * File Name:    triangle.c
 * Author:       basilguo@163.com
 * Created Time: 2022-03-26 04:55:31
 * Description:
 ************************************************************************/

#include <stdio.h>
#include <stdlib.h>

int main(void)
{
    int a, b, c;
    scanf("%d %d %d", &a, &b, &c);

    if (a >= b+c || b >= a+c || c >= a+b)
    {
        printf("no\n");
    }
    else
    {
        printf("yes\n");
    }

    return 0;
}
