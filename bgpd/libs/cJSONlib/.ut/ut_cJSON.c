#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cJSON.h"

int main(int argc, char *argv[])
{
    size_t ret;
    FILE *fp = NULL;

    char buff[1024] = {0, };

    if (argc < 2) {
        printf("Usage: json-file.\n");
        return -1;
    }

    fp = fopen(argv[1], "ro");
    if (fp == NULL) {
        printf("open file failed.\n");
        return -1;
    }

    ret = fread(buff, 1, sizeof(buff), fp);
    if (ret == 0) {
        printf("read file successfull.\n");
    }

    cJSON * root = cJSON_Parse(buff);
    cJSON *format = cJSON_GetObjectItem(root, "format");
    int framerate = cJSON_GetObjectItem(format, "frame rate")->valueint;
    printf("framerate is %d.\n", framerate);

    return 0;
}
