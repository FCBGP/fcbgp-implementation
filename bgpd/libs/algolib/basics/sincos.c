/*************************************************************************
 * File Name:    sincos.c
 * Author:       basilguo@163.com
 * Created Time: 2022-03-26 04:40:51
 * Description:
 ************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#define PI 3.1415926

int main(void)
{
    int n;
    scanf("%d", &n);

    printf("sin(n) = %.3lf\n", sin(n));
    printf("cos(n) = %.3lf\n", cos(n));

    return 0;
}
