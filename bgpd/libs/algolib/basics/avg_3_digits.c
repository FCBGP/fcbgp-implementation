/*************************************************************************
 * File Name:    avg_3_digits.c
 * Author:       basilguo@163.com
 * Created Time: 2022-03-26 04:38:34
 * Description:
 ************************************************************************/

#include <stdio.h>
#include <stdlib.h>

int main(void)
{
    int a, b, c;
    scanf("%d %d %d", &a, &b, &c);

    printf("%.3lf\n", (a+b+c)/3.0);

    return 0;
}
