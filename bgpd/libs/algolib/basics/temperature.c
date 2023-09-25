/*************************************************************************
 * File Name:    temperature.c
 * Author:       basilguo@163.com
 * Created Time: 2022-03-26 04:39:43
 * Description:
 ************************************************************************/

#include <stdio.h>
#include <stdlib.h>

int main(void)
{
    double f, c;
    scanf("%lf", &f);

    c = 5 * (f-32) / 9;

    printf("%lf", c);

    return 0;
}
