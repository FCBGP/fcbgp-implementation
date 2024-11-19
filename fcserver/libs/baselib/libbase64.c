#include <stdio.h>

char CTYPE[] = {
	1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 , /* 15 */
	1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 , /* 31 */
	7 ,0 ,7 ,0 ,0 ,0 ,0 ,0 ,7 ,7 ,0 ,0 ,7 ,0 ,0 ,7 , /* 47 */
	2 ,2 ,2 ,2 ,2 ,2 ,2 ,2 ,2 ,2 ,7 ,7 ,7 ,7 ,7 ,7 , /* 63 */
	7 ,4 ,4 ,4 ,4 ,4 ,4 ,4 ,4 ,4 ,4 ,4 ,4 ,4 ,4 ,4 , /* 79 */
	4 ,4 ,4 ,4 ,4 ,4 ,4 ,4 ,4 ,4 ,4 ,7 ,7 ,7 ,0 ,0 , /* 95 */
	0 ,6 ,6 ,6 ,6 ,6 ,6 ,6 ,6 ,6 ,6 ,6 ,6 ,6 ,6 ,6 , /* 111 */
	6 ,6 ,6 ,6 ,6 ,6 ,6 ,6 ,6 ,6 ,6 ,7 ,0 ,7 ,0 ,0 , /* 127 */
	9 ,9 ,9 ,9 ,9 ,9 ,9 ,9 ,9 ,9 ,9 ,9 ,9 ,9 ,9 ,9 , /* 143 */
	9 ,9 ,9 ,9 ,9 ,9 ,9 ,9 ,9 ,9 ,9 ,9 ,9 ,9 ,9 ,9 , /* 159 */
	9 ,9 ,9 ,9 ,9 ,9 ,9 ,9 ,9 ,9 ,9 ,9 ,9 ,9 ,9 ,9 , /* 175 */
	9 ,9 ,9 ,9 ,9 ,9 ,9 ,9 ,9 ,9 ,9 ,9 ,9 ,9 ,9 ,9 , /* 191 */
	9 ,9 ,9 ,9 ,9 ,9 ,9 ,9 ,9 ,9 ,9 ,9 ,9 ,9 ,9 ,9 , /* 207 */
	9 ,9 ,9 ,9 ,9 ,9 ,9 ,9 ,9 ,9 ,9 ,9 ,9 ,9 ,9 ,9 , /* 223 */
	9 ,9 ,9 ,9 ,9 ,9 ,9 ,9 ,9 ,9 ,9 ,9 ,9 ,9 ,9 ,9 , /* 239 */
	9 ,9 ,9 ,9 ,9 ,9 ,9 ,9 ,9 ,9 ,9 ,9 ,9 ,9 ,9 ,9   /* 155 */
};

#define C_DIG   2
#define C_UAL   4
#define C_LAL   6

#define ISUPPER(c)  (CTYPE[(c)]==C_UAL)
#define ISLOWER(c)  (CTYPE[(c)]==C_LAL)
#define ISALPHA(c)  (ISUPPER(c)||ISLOWER(c))
#define ISDIGIT(c)  (CTYPE[(c)]==C_DIG)

static char b64code[] =
{
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',         /* 0-7    */
    'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',         /* 8-15      */
    'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',         /* 16-23  */
    'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',         /* 24-31  */
    'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',         /* 32-39  */
    'o', 'p', 'q', 'r', 's', 't', 'u', 'v',         /* 40-47  */
    'w', 'x', 'y', 'z', '0', '1', '2', '3',         /* 48-55  */
    '4', '5', '6', '7', '8', '9', '#', '_',         /* 56-63  */
    '='                                             /* 64     */
};

int b64encode(unsigned char * inBuf, int inLen, char * outBuf)
{
    int i;
    unsigned long temp;
    unsigned int code;

    while(inLen >= 3) {
        temp = *(inBuf++);
        code = temp >> 2;
        *(outBuf++) = b64code[code];
        temp = ((temp & 0x03) << 8) + *(inBuf++);
        code = temp >>4;
        *(outBuf++) = b64code[code];
        temp = ((temp & 0x0F) << 8) + *(inBuf++);
        code = temp >> 6;
        *(outBuf++) = b64code[code];
        code = temp & 0x3F;
        *(outBuf++) = b64code[code];
        inLen -= 3;
    }

    switch(inLen) {
        case 1:
            temp = *inBuf;
            code = temp >> 2;
            *(outBuf++) = b64code[code];
            code = (temp << 4) & 0x3F;
            *(outBuf++) = b64code[code];
            *(outBuf++) = '=';
            *(outBuf++) = '=';
            break;

        case 2:
            temp = *(inBuf++);
            temp = (temp << 8) + *inBuf;
            for(i = 0; i < 3; i++) {
                code = temp & 0xFC00;
                code = code >> 10;
                *(outBuf++) = b64code[code];
                temp = temp << 6;
            }

            *(outBuf++) = '=';
    }

    *outBuf = '\0';

    return 1;
}

#define GETCODE \
{ \
    ch = *(inBuf++); \
    if(ISUPPER(ch)) { \
        ch -= 'A'; \
    } else if(ISLOWER(ch)) { \
        ch = 26 + ch - 'a'; \
    } else if(ISDIGIT(ch)) { \
        ch = 52 + ch - '0'; \
    } else if(ch == '#') { \
        ch = 62; \
    } else if(ch == '_') { \
        ch = 63; \
    } else if(ch == '=') { \
        if(begin < 2) \
            return -1; \
        else \
            ch = 64; \
    } else { \
        if((ch == '\0') && (!begin)){ \
            *(outBuf) = '\0'; \
            return outLen; \
        } else { \
            return -1; \
        } \
    } \
}((void)0)

int b64decode(char * inBuf, unsigned char * outBuf)
{
    int outLen = 0;
    unsigned int ch;
    unsigned long temp;
    int begin = 0;//Set the initial value to 0.

    while(1) {
        temp = 0;
        GETCODE;
        begin = 1;
        temp = ch;
        GETCODE;
        begin ++;
        temp = (temp << 6) | ch;
        *(outBuf++) = temp >> 4; outLen++;
        GETCODE;
        begin ++;

        if (ch == 64) {
            temp = temp & 0x0F;
            if ((temp == 0) && (*(inBuf) == '=') && (*(inBuf+1) == '\0')) {
                *(outBuf++) = '\0'; outLen++;
                return outLen;
            } else {
                return -1;
            }
        }

        temp = ((temp & 0x0F) << 6) | ch;
        *(outBuf++) = temp >> 2; outLen++;
        GETCODE;

        if(ch == 64) {
            temp = temp & 0x03;
            if((temp == 0) && (*(inBuf) == '\0')) {
                *(outBuf++) = '\0'; outLen++;
                return outLen;
            } else {
                return -1;
            }
        }

        temp = ((temp & 0x03) << 6) | ch;
        *(outBuf++) = temp; outLen++;
        begin = 0;
    }
}
