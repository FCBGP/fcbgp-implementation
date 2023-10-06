#include "hex.h"

int str2hex(const char *str, char *hex)
{
    int i = 0;
    int j = 0;
    char c;
    char *pchar;
    char tmp[2048] = {0};
    memset(tmp, 0, sizeof(tmp));

    pchar = tmp;
    for (i=0; i<strlen(str); i++) {
        c = str[i];
        if (c == ':') {
            continue;
        } else if(((c >= '0') && (c <= '9')) || ((c >= 'a') && (c <= 'f')) || ((c >= 'A') && (c <= 'F'))) {
            *pchar++ = c;
        } else {
            printf("INPUT WRONG!!!.\n");
            return -1;
        }
    }

    pchar = hex;
    if(strlen(tmp)%2 != 0){
        c = tmp[0];
        if ((c >= '0') && (c <= '9')) {
            *pchar = (c - '0');
        } else if((c >= 'a') && (c <= 'f')) {
            *pchar = (c - 'a' + 10);
        } else if ((c >= 'A') && (c <= 'F')) {
            *pchar = (c - 'A' + 10);
        }
        pchar++;
        j = 1;
    }
    for(i=j; i<strlen(tmp); i+=2) {
        c = tmp[i];
        if ((c >= '0') && (c <= '9')) {
            *pchar = (c - '0') << 4;
        } else if((c >= 'a') && (c <= 'f')) {
            *pchar = (c - 'a' + 10) << 4;
        } else if ((c >= 'A') && (c <= 'F')) {
            *pchar = (c - 'A' + 10) << 4;
        }

        c = tmp[i+1];
        if ((c >= '0') && (c <= '9')) {
            *pchar |= (c - '0');
        } else if((c >= 'a') && (c <= 'f')) {
            *pchar |= (c - 'a' + 10);
        } else if ((c >= 'A') && (c <= 'F')) {
            *pchar |= (c - 'A' + 10);
        }
        pchar++;
    }

    return 0;
}



