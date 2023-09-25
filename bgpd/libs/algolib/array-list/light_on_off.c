/*************************************************************************
 * File Name:    light_on_off.c
 * Author:       basilguo@163.com
 * Created Time: 2022-03-27 01:44:24
 * Description:  开灯问题：每个人都按一下自己编号倍数的开关，最后的灯情况。默认灯关闭。
 ************************************************************************/

#include <stdio.h>
#include <stdlib.h>

#define MAX_LIGHT (1000 + 10)

int main(void)
{
    // INPUT: k人，n灯
    // OUTPUT: 最后灯情况
    int lights[MAX_LIGHT] = {0};
    int k, n;

    scanf("%d %d", &n, &k);

    for (int i=1; i<=k; ++i)
    {
        for (int j=1; i*j<=n; ++j)
        {
            /*
            if (lights[i*j] == 1) lights[i*j] = 0;
            else lights[i*j] = 1;
            */
            lights[i*j] ^= 1;
        }
    }

    for (int i=1; i<=n; ++i)
    {
        if (lights[i] == 1)
        {
            printf("%4d", i);
        }
    }

    printf("\n");

    return 0;
}
