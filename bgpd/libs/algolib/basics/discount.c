/*************************************************************************
 * File Name:    discount.c
 * Author:       basilguo@163.com
 * Created Time: 2022-03-26 04:50:43
 * Description:
 ************************************************************************/

#include <stdio.h>
#include <stdlib.h>

int main(void)
{
    int num;
    double total = 0;
    const int Price = 95;
    const int DiscountTotal = 300;
    const double Rate = 0.85;

    scanf("%d", &num);

    total = Price * num;

    if (total >= 300)
        total *= Rate;

    printf("%.2lf\n", total);

    return 0;
}
