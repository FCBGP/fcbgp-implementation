/*************************************************************************
 * File Name:    sort_3_int.c
 * Author:       basilguo@163.com
 * Created Time: 2022-03-26 04:35:15
 * Description:
 ************************************************************************/

#include <stdio.h>
#include <stdlib.h>

int main(void)
{
    int a, b, c;
    int min, max, mid;
    printf("INPUT: ");
    scanf("%d %d %d", &a, &b, &c);

    max = (a>b ? (a>c?a:c) : (b>c?b:c));
    min = (a<b ? (a<c?a:c) : (b<c?b:c));
    mid = a+b+c-max-min;

    printf("OUTPUT: %d %d %d\n", min, mid, max);

    return 0;
}
