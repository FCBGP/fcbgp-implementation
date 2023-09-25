/*************************************************************************
 * File Name:    reverse_trianble.c
 * Author:       basilguo@163.com
 * Created Time: 2022-03-26 06:15:02
 * Description:
 ************************************************************************/

#include <stdio.h>
#include <stdlib.h>

int main(void)
{
    int n;
    scanf("%d", &n);

    for (int i=0; i<n; ++i)
    {
        for (int j=0; j<i; ++j)
            printf(" ");
        for (int j=0; j<2*(n-i)-1; ++j)
            printf("#");
        printf("\n");
    }

    return 0;
}
