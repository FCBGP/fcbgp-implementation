/*************************************************************************
 * File Name:    light_on_off.c
 * Author:       basilguo@163.com
 * Created Time: 2022-03-27 01:44:24
 * Description:  �������⣺ÿ���˶���һ���Լ���ű����Ŀ��أ����ĵ������Ĭ�ϵƹرա�
 ************************************************************************/

#include <stdio.h>
#include <stdlib.h>

#define MAX_LIGHT (1000 + 10)

int main(void)
{
    // INPUT: k�ˣ�n��
    // OUTPUT: �������
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
