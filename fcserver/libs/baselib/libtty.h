#ifndef _LIBTTY_H_
#define _LIBTTY_H_

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#include <termios.h>
#include <unistd.h>

extern int tty_set(struct termios* oldtermset, int noecho);
extern int tty_reset(struct termios* oldtermset);
extern int tty_getchar(char* ch, int timeout, int noecho);
extern int tty_gets(char* buf, int size, int timeout, int noecho);

#endif
