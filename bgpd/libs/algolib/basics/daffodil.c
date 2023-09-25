/*************************************************************************
 * File Name:    daffodil.c
 * Author:       basilguo@163.com
 * Created Time: 2022-03-26 05:10:12
 * Description:
 ************************************************************************/

#include <stdio.h>
#include <stdlib.h>

int main(void)
{
    // INPUT: no input.
    // OUTPUT: all daffodil between 100 and 999
    // ABC = A^3 + B^3 + C^3

    for (int n = 100; n < 1000; ++n)
    {
        int a = n/100;
        int b = n/10%10;
        int c = n%10;

        if (n == a*a*a + b*b*b + c*c*c)
            printf("%d\n", n);
    }

    return 0;
}
