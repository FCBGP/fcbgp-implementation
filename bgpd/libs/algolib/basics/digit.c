/*************************************************************************
 * File Name:    digit.c
 * Author:       basilguo@163.com
 * Created Time: 2022-03-26 05:07:10
 * Description:
 ************************************************************************/

#include <stdio.h>
#include <stdlib.h>

int main(void)
{
    // INPUT: no bigger than 10^9 integer
    // OUTPUT: total bits.
    int bits = 1;
    unsigned long num;

    scanf("%ld", &num);

    while (num > 10)
    {
        num /= 10;
        bits ++;
    }

    printf("%d\n", bits);

    return 0;
}
