/*************************************************************************
 * File Name:    hex2digit.c
 * Author:       basilguo@163.com
 * Created Time: 2022-02-20 09:33:43
 * Description:  Hex to digits.
 ************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>

long long hex2dig(char *hex_str)
{
    long long rs = 0;
    int len = strlen(hex_str);
    int i = 0;

    while (i < len)
    {
        if (isalpha(hex_str[i]))
            rs = rs * 16 + (toupper(hex_str[i]) - 'A') + 10;
        else
            rs = rs * 16 + (hex_str[i] - '0');

        i++;
    }

    return rs;
}

#ifdef MAIN
int main(void)
{
    char hex_str[100];
    printf("Inputs an hex: ");
    scanf("%s", hex_str);
    long long num = hex2dig(hex_str);
    printf("The digit is %llu.\n", num);
}
#endif
