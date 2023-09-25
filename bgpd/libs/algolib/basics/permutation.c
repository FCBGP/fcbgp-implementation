/*************************************************************************
 * File Name:    permutation.c
 * Author:       basilguo@163.com
 * Created Time: 2022-03-27 01:30:15
 * Description:
 ************************************************************************/

#include <stdio.h>
#include <stdlib.h>

int main(void)
{
    // The 1-9, abc:def:ghi = 1:2:3
    for (int a=1; a<=3; ++a)
    {
        for (int b=1; b<=9; ++b)
        {
            for (int c=1; c<=9; ++c)
            {
                if (a!=b && a!=c && b!=c)
                {
                    int abc = a*100 + b*10 +c;
                    int def = 2 * abc;
                    int ghi = 3 * abc;

                    if (ghi > 999) break;

                    int d=def/100, e=def/10%10, f=def%10;
                    int g=ghi/100, h=ghi/10%10, i=ghi%10;

                    if (0==d || 0==e || 0==f
                            || 0==g || 0==h || 0==i)
                        continue;

                    if (a!=d && a!=e && a!=f && a!=g && a!=h && a!=i
                            && b!=d && b!=e && b!=f && b!=g && b!=h && b!=i
                            && c!=d && c!=e && c!=f && c!=g && c!=h && c!=i
                            && d!=e && d!=f && d!=g && d!=h && d!=i
                            && e!=f && e!=g && e!=h && e!=i
                            && f!=g && f!=h && f!=i
                            && g!=h && g!=i
                            && h!=i)
                    {
                        printf("%d:%d:%d = %d:%d:%d\n", abc, def, ghi, abc/abc,
                                def/abc, ghi/abc);
                    }

                }
            }
        }
    }
}
