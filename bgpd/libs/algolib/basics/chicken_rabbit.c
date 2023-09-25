/*************************************************************************
 * File Name:    chicken_rabbit.c
 * Author:       basilguo@163.com
 * Created Time: 2022-03-26 04:30:25
 * Description:
 ************************************************************************/

#include <stdio.h>
#include <stdlib.h>

int main(void)
{
    // INPUT:  total_num: n, total_legs: m
    // OUTPUT: chicken: a, rabbit: b
    int n, m;
    int a, b;
    scanf("%d %d", &n, &m);

    a = (4*n-m) / 2;
    b = n - a;

    if (a>=0 && b>=0 && 2*a + 4*b == m)
    {
        printf("chicken: %d, rabbit: %d\n", a, b);
    }
    else
    {
        printf("No answer\n");
    }

    return 0;
}
