#include "libtty.h"

int tty_set(struct termios *oldtermset, int noecho)
{
    struct termios termset;

    if (tcgetattr(STDIN_FILENO, &termset) < 0) {
        return -ENOTTY;
    }

    memcpy(oldtermset, &termset, sizeof(struct termios));

    if (noecho) {
        termset.c_lflag &= ~(ECHO|ECHOE|ECHOK|ISIG);
    } else {
        termset.c_lflag |= (ECHO|ECHOE|ECHOK|ISIG);
    }

    termset.c_cc[VMIN] = 1;
    termset.c_cc[VTIME] = 0;

    if (tcsetattr(STDIN_FILENO, TCSANOW, &termset)< 0) {
        return -ENOTTY;
    }

    return 0;
}

int tty_reset(struct termios *oldtermset)
{
    if (tcsetattr(STDIN_FILENO, TCSANOW, oldtermset) < 0) {
        return -ENOTTY;
    }

    return 0;
}

int tty_getchar(char *ch, int timeout, int noecho)
{
    int ret;
    struct termios oldtermset;

    if (tty_set(&oldtermset, noecho) < 0) {
        return -ENOTTY;
    }

    if (timeout) {
        fd_set fdset;
        struct timeval tv;

        FD_ZERO(&fdset);
        FD_SET(STDIN_FILENO, &fdset);

        tv.tv_sec = timeout;
        tv.tv_usec = 0;

        ret = select(STDIN_FILENO + 1, &fdset, NULL, NULL, &tv);
        if (ret == 0) {
            ret = -ETIMEDOUT;
            goto out;
        }

        if (ret < 0) {
            ret = -errno;
            goto out;
        }
    }

    ret = read(STDIN_FILENO, ch, 1);
    if (ret < 0) {
        ret = -errno;
        goto out;
    }

out:
    if (tty_reset(&oldtermset) < 0) {
        return -ENOTTY;
    }

    return ret;
}

int tty_gets(char *buf, int size, int timeout, int noecho)
{
    int i;
    int ret;
    char ch;

    fflush(NULL);
    for (i=0; i<size; i++) {
        ret = tty_getchar(&ch, timeout, noecho);
        if (ret < 0) {
            putchar('\n');
            tcflush(STDIN_FILENO, TCIOFLUSH);
            fflush(NULL);
            return ret;
        }

        /* EOF */
        if (ret == 0) {
            putchar('\n');
            buf[i] = '\0';
            break;
        }

        /* EOL */
        if (ch == '\r' || ch == '\n') {
            if (i == 0 && noecho) {
                putchar('\n');
            }
            buf[i] = '\0';
            break;
        }

        buf[i] = ch;
    }

    tcflush(STDIN_FILENO, TCIOFLUSH);
    fflush(NULL);
    return i;
}
