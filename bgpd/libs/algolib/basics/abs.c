/*************************************************************************
 * File Name:    abs.c
 * Author:       basilguo@163.com
 * Created Time: 2022-03-26 04:54:06
 * Description:
 ************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <math.h>

int main(void)
{
    double fnum;

    scanf("%lf", &fnum);

    printf("%.2lf\n", fabs(fnum));

    return 0;
}
