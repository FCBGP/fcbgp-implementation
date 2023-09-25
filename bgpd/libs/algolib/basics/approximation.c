/*************************************************************************
 * File Name:    approximation.c
 * Author:       basilguo@163.com
 * Created Time: 2022-03-27 01:24:58
 * Description:  ½üËÆ¼ÆËã
 ************************************************************************/

#include <stdio.h>
#include <stdlib.h>

int main(void)
{
    // INPUT: none
    // OUTPUT: the approximation of PI/4
    double rs = 0;
    int base = 1;
    int flag = -1;

    while (1)
    {
        double num = 1.0/base;
        if (num < 1e-6)
        {
            break;
        }

        flag *= -1;
        rs += flag * num;
        base += 2;
    }

    printf("%lf\n", rs);

    return 0;
}
