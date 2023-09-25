/*************************************************************************
 * File Name:    reverse_three_digits.c
 * Author:       basilguo@163.com
 * Created Time: 2022-03-26 04:24:39
 * Description:
 ************************************************************************/

#include <stdio.h>
#include <stdlib.h>

void reverse3digits()
{
    int n, m;
    scanf("%d", &n);
    m = (n%10)*100 + (n/10%10)*10 + n/100;
    printf("%d\n", m);
}

int main(void)
{
    reverse3digits();

    return 0;
}
