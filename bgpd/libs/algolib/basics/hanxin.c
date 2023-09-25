/*************************************************************************
 * File Name:    hanxin.c
 * Author:       basilguo@163.com
 * Created Time: 2022-03-26 05:13:37
 * Description:
 ************************************************************************/

#include <stdio.h>
#include <stdlib.h>

int main(void)
{
    // INPUT:a<3, b<5, c<7
    // OUTPUT: the minimal soilders.
    // 10<=soilders<100
    int a, b, c;
    int total = 10;

    scanf("%d %d %d", &a, &b, &c);

    while (total < 100)
    {
        if (total%3==a && total%5==b && total%7==c)
        {
            printf("total is %d\n", total);
            return 0;
        }
        total ++;
    }

    printf("No answer\n");

    return 0;
}
