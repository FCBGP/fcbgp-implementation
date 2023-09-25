/*************************************************************************
 * File Name:    swap_two_var.c
 * Author:       basilguo@163.com
 * Created Time: 2022-03-26 04:27:44
 * Description:
 ************************************************************************/

#include <stdio.h>
#include <stdlib.h>

int main(void)
{
    int a, b, ab;

    scanf("%d %d", &a, &b);

    a = a^b;
    b = a^b;
    a = a^b;

    printf("%d %d\n", a, b);

    return 0;
}
