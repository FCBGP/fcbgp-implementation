#include "libcrc32.h"
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char* argv[])
{
    int src = 0xb801051c;
    uint32_t res = 0;
    char src_c[] = {0xb8, 0x01, 0x05, 0x1c, 0x00};
    res = crc32_run(0, (char*)&src, 4);
    printf("0 int %x.\n", res);
    res = crc32_run(0, src_c, 4);
    printf("0 char[] %x.\n", res);

    res = crc32_run(0x104c11db7, (char*)&src, 4);
    printf("0x104c11db7 int %x.\n", res);
    res = crc32_run(0x104c11db7, src_c, 4);
    printf("0x104c11db7 char[] %x.\n", res);

    res = crc32_run(0x104c11db, (char*)&src, 4);
    printf("0x104c11db int %x.\n", res);
    res = crc32_run(0x104c11db, src_c, 4);
    printf("0x104c11db char[] %x.\n", res);

    return 0;
}
