/*************************************************************************
 * File Name:    leap_year.c
 * Author:       basilguo@163.com
 * Created Time: 2022-03-26 04:56:57
 * Description:
 ************************************************************************/

#include <stdio.h>
#include <stdlib.h>

int main(void)
{
    int year;
    scanf("%d", &year);

    if (year % 400 == 0 ||
            year % 100 != 0 && year % 4 == 0)
        printf("%d is a leap year\n", year);
    else
        printf("%d is no a leap year\n", year);

    return 0;
}
