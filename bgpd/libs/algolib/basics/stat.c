/*************************************************************************
 * File Name:    stat.c
 * Author:       basilguo@163.com
 * Created Time: 2022-03-26 06:17:12
 * Description:
 ************************************************************************/

#include <stdio.h>
#include <stdlib.h>

int main(void)
{
    // count n numbers that whose value less than m.
    int n, a, m, cnt=0;
    scanf("%d", &n);
    int *arr = (int*)malloc(sizeof(int)*n);

    for (int i=0; i<n; ++i)
    {
        scanf("%d", &arr[i]);
    }

    scanf("%d", &m);

    for (int i=0; i<n; ++i)
    {
        if (arr[i] < m) cnt ++;
    }

    printf("%d\n", cnt);


    free(arr);

    return 0;
}
