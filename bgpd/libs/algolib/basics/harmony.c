/*************************************************************************
 * File Name:    harmony.c
 * Author:       basilguo@163.com
 * Created Time: 2022-03-27 01:22:46
 * Description:  调和级数
 ************************************************************************/

#ifndef _TYPE
#define _TYPE double
#endif

_TYPE  harmony(int n)
{
    int i = 1;
    double ret = 0;

    for (i=1; i<=n; ++i)
    {
        ret += 1.0 / i;
    }

    return ret;
}

#ifdef _MAIN

#include <stdio.h>
#include <stdlib.h>

int main(void)
{
    _TYPE rs = 0;
    int n = 0;

    printf("n = ");
    scanf("%d", &n);

    rs = harmony(n);

    printf("%.3lf\n", rs);

    return 0;
}

#endif
