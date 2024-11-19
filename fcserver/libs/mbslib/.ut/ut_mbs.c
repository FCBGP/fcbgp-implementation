#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <ctype.h>
#include <errno.h>

#include "libmbs.h"

int cut_mbsnewsize(int argc, char *argv[])
{
    mbs_t mbs = NULL;
    mbs = mbsnewsize(100);
    printf("mbs=[%s]\n", mbs);
    mbsdump(mbs);
    mbsfree(mbs);

    return 0;
}

int cut_mbsnew(int argc, char *argv[])
{
    mbs_t mbs = NULL;
    mbs = mbsnew("hello world\n");
    printf("mbs=[%s]\n", mbs);
    mbsdump(mbs);
    mbsfree(mbs);

    return 0;
}

int cut_mbsdup(int argc, char *argv[])
{
    mbs_t mbs = NULL;
    mbs_t mbs2 = NULL;
    mbs = mbsnew("hello world\n");
    mbs2 = mbsdup(mbs);
    printf("mbs2=[%s]\n", mbs2);
    mbsdump(mbs2);
    mbsfree(mbs2);
    mbsfree(mbs);

    return 0;
}

int cut_mbssetlen(int argc, char *argv[])
{
    mbs_t mbs = NULL;

    mbs = mbsnew("foobar");
    mbs[2] = '\0';
    printf("%d ", mbslen(mbs)); // 6
    mbssetlen(mbs, 2);
    printf("%d\n", mbslen(mbs)); // 2
    mbsfree(mbs);

    return 0;
}

int cut_mbsinclen(int argc, char *argv[])
{
    int rdlen;
    int blksize = 128;
    mbs_t mbs = NULL;

    int fd = open("mbs", O_RDONLY);
    if (fd < 0) {
        return -ENOENT;
    }

    if (mbsexpand(&mbs, blksize) == NULL) {
        mbsfree(mbs);
        return -ENOMEM;
    }

    while (1) {
        int len = mbslen(mbs);
        int size = mbssize(mbs);

        if (len + blksize >= size) {
            printf("mbslen %d mbssize %d need expand.\n", len, size);
            if (mbsexpand(&mbs, blksize) == NULL) {
                mbsfree(mbs);
                return -ENOMEM;
            }
            printf("now mbslen %d mbssize %d.\n", mbslen(mbs), mbssize(mbs));
        }

        rdlen = read(fd, mbs + len, blksize);
        if (rdlen <= 0) {
            break;
        }

        mbsinclen(mbs, rdlen);
        printf("rdlen %d, mbslen %d, mbssize %d\n", rdlen, mbslen(mbs), mbssize(mbs));
    }

    mbsdump(mbs);
    mbsfree(mbs);

    return 0;
}

int cut_mbscat(int argc, char *argv[])
{
    mbs_t mbs = NULL;

    mbscat(&mbs, "hello");
    mbscat(&mbs, "world");
    mbscat(&mbs, "\0");

    mbsdump(mbs);
    mbsfree(mbs);

    return 0;
}

int cut_mbscatfmt(int argc, char *argv[])
{
    mbs_t mbs = NULL;

    mbscat(&mbs, "{");
    mbscatfmt(&mbs, "\"code\":%d,", 5);
    mbscatfmt(&mbs, "\"result\":\"%s\"", "google");
    mbscat(&mbs, "}");

    mbsdump(mbs);
    mbsfree(mbs);

    return 0;
}

int cut_mbsaddfmt(int argc, char *argv[])
{
    mbs_t mbs = NULL;

    mbsaddfmt(&mbs, "%d", 6);
    mbsaddfmt(&mbs, "%s", "hello");
    mbsaddfmt(&mbs, "%s", "world");
    mbsaddfmt(&mbs, "%s", "I");
    mbsaddfmt(&mbs, "%s", "am");
    mbsaddfmt(&mbs, "%s", "the");
    mbsaddfmt(&mbs, "%s", "boss");

    mbsdump(mbs);
    mbsfree(mbs);

    return 0;
}

int cut_mbsjoin(int argc, char *argv[])
{
    mbs_t mbs = NULL;

    mbsjoin(&mbs, argc, argv, " ");

    mbsdump(mbs);
    mbsfree(mbs);

    return 0;
}

int cut_mbssum(int argc, char *argv[])
{
    mbs_t mbs = NULL;

    mbssum(&mbs, argc, argv);

    mbsdump(mbs);
    mbsfree(mbs);

    return 0;
}

int cut_mbssumex(int argc, char *argv[])
{
    mbs_t mbs = NULL;

    mbsaddfmt(&mbs, "%d", argc);
    mbssum(&mbs, argc, argv);
    mbsaddfmt(&mbs, "%s", "\r\n\r\n");

    mbsdump(mbs);
    mbsfree(mbs);

    return 0;
}

int cut_mbscatmem(int argc, char *argv[])
{
    mbs_t mbs = NULL;

    mbscatmem(&mbs, argv, 16);

    mbsdump(mbs);
    mbsfree(mbs);

    return 0;
}

int cut_mbscatstdout(int argc, char *argv[])
{
    mbs_t mbs = NULL;

    mbscatstdout(&mbs, "ls -l");

    mbsdump(mbs);
    mbsfree(mbs);

    return 0;
}

int cut_mbscatstdoutvargs(int argc, char *argv[])
{
    mbs_t mbs = NULL;

    mbscatstdoutvargs(&mbs, "ls -l | grep %s", "mbs");

    mbsdump(mbs);
    mbsfree(mbs);

    return 0;
}

int cut_mbsreadline(int argc, char *argv[])
{
    FILE *fp = NULL;
    mbs_t mbs = NULL;

    if (argc > 1) {
        fp = fopen(argv[1], "r");
        if (fp == NULL) {
            return -ENOENT;
        }
    } else {
        fp = stdin;
    }

    while (1) {
        mbs = mbsreadline(fp);
        if (mbs == NULL) {
            break;
        }

        mbsdump(mbs);
        mbsfree(mbs);
    }

    fclose(fp);
    return 0;
}

int cut_mbsmemmove(int argc, char *argv[])
{
    int i = 0;
    int cnt = 0;
    mbs_t list = NULL;

    list = mbsnewsize(64);

    while (1) {
        if (i == 100) {
            break;
        }

        if (cnt > 64) {
            int len;
            int offset = 0;
            char *p = strchr(list, ',');
            if (p) {
                offset = p + 1 - list;
                len = mbslen(list) - offset;
                memmove(list, p + 1, len + 1);
                mbssetlen(list, len);
                list[len] = '\0';
            }
            cnt--;
        }

        if (cnt == 0) {
            mbscatfmt(&list, "%d", i);
        } else {
            mbscatfmt(&list, ",%d", i);
        }

        cnt++;
        i++;

        printf("i=%d, cnt=%d\n", i, cnt);
        mbsdump(list);
    }

    mbsfree(list);
    return 0;
}

int cut_mbsendian(int argc, char *argv[])
{
    mbs_t mbs = NULL;

    mbscato(&mbs, 0xFF);
    mbsdump(mbs);
    mbscaths(&mbs, 0xEEDD);
    mbsdump(mbs);
    mbscathl(&mbs, 0xCCBBAA99);
    mbsdump(mbs);
    mbscathll(&mbs, 0x8877665580706050LL);
    mbsdump(mbs);
    mbscatns(&mbs, 0xEEDD);
    mbsdump(mbs);
    mbscatnl(&mbs, 0xCCBBAA99);
    mbsdump(mbs);
    mbscatnll(&mbs, 0x8877665580706050LL);
    mbsdump(mbs);

    mbsfree(mbs);
    return 0;
}

int cut_mbscattodeath(int argc, char *argv[])
{
    char i = 0;
    mbs_t mbs = NULL;

    // this will failed after loop 1073741823 times.
    while (1) {
        if (mbscatchar(&mbs, i) == NULL) {
            printf("%d\n", mbslen(mbs));
            break;
        }

        if (mbslen(mbs) % 1000000 == 0) {
            printf("%d\n", mbslen(mbs));
        }

        i++;
    }

    return 0;
}

int main(int argc, char *argv[])
{
    mbsinit(0);

    cut_mbsnewsize(argc, argv);
    cut_mbsnew(argc, argv);
    cut_mbsdup(argc, argv);
    cut_mbssetlen(argc, argv);
    cut_mbsinclen(argc, argv);
    cut_mbscat(argc, argv);
    cut_mbscatfmt(argc, argv);
    cut_mbsaddfmt(argc, argv);
    cut_mbsjoin(argc, argv);
    cut_mbssum(argc, argv);
    cut_mbssumex(argc, argv);
    cut_mbscatmem(argc, argv);
    cut_mbscatstdout(argc, argv);
    cut_mbscatstdoutvargs(argc, argv);
    cut_mbsreadline(argc, argv);
    cut_mbsmemmove(argc, argv);
    cut_mbsendian(argc, argv);
    cut_mbscattodeath(argc, argv);

    mbsfini();
    return 0;
}
