/*************************************************************************
 * File Name:    aabb.c
 * Author:       basilguo@163.com
 * Created Time: 2022-03-26 04:58:49
 * Description:
 ************************************************************************/

#include <stdio.h>
#include <stdlib.h>

int is_sqrt(int num)
{
    int i=32;

    for (i=32; i*i!=num && i*i<=9999; ++i)
        ;
    return num == i*i;
}

int main(void)
{
    // output each `aabb`-like numbers.
    int a, b;
    for (a=1; a<=9; ++a)
    {
        for (b=0; b<=9; ++b)
        {
            if (is_sqrt(a*1100+b*11))
            {
                printf("%d\n", a*1100+b*11);
            }
        }
    }
    return 0;
}
