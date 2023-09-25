#ifndef __LIBBASE64_H__
#define __LIBBASE64_H__

extern int b64encode(unsigned char * inBuf, int inLen, char * outBuf);
extern int b64decode(char * inBuf, unsigned char * outBuf);

#endif
