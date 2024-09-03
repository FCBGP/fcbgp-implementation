/**
 * @file colorp.h
 * @author basilguo@163.com
 * @brief color printf
 * @version 0.0.1
 * @date 2024-09-02
 *
 * @copyright Copyright (c) 2021 - 2024
 */
#ifndef COLORP_H
#define COLORP_H

#ifdef __cplusplus
extern "C"
{
#endif /* __cplusplus */

#include <stdarg.h>

#define TXTBLK(fmt, ...) printf("\033[0;30m" fmt "\033[0m", ##__VA_ARGS__);
#define TXTRED(fmt, ...) printf("\033[0;31m" fmt "\033[0m", ##__VA_ARGS__);
#define TXTGRN(fmt, ...) printf("\033[0;32m" fmt "\033[0m", ##__VA_ARGS__);
#define TXTYLW(fmt, ...) printf("\033[0;33m" fmt "\033[0m", ##__VA_ARGS__);
#define TXTLUN(fmt, ...) printf("\033[0;34m" fmt "\033[0m", ##__VA_ARGS__);
#define TXTPUR(fmt, ...) printf("\033[0;35m" fmt "\033[0m", ##__VA_ARGS__);
#define TXTCYN(fmt, ...) printf("\033[0;36m" fmt "\033[0m", ##__VA_ARGS__);
#define TXTWHT(fmt, ...) printf("\033[0;37m" fmt "\033[0m", ##__VA_ARGS__);

#define BLDBLK(fmt, ...) printf("\033[1;30m" fmt "\033[0m", ##__VA_ARGS__);
#define BLDRED(fmt, ...) printf("\033[1;31m" fmt "\033[0m", ##__VA_ARGS__);
#define BLDGRN(fmt, ...) printf("\033[1;32m" fmt "\033[0m", ##__VA_ARGS__);
#define BLDYLW(fmt, ...) printf("\033[1;33m" fmt "\033[0m", ##__VA_ARGS__);
#define BLDLUN(fmt, ...) printf("\033[1;34m" fmt "\033[0m", ##__VA_ARGS__);
#define BLDPUR(fmt, ...) printf("\033[1;35m" fmt "\033[0m", ##__VA_ARGS__);
#define BLDCYN(fmt, ...) printf("\033[1;36m" fmt "\033[0m", ##__VA_ARGS__);
#define BLDWHT(fmt, ...) printf("\033[1;37m" fmt "\033[0m", ##__VA_ARGS__);

#define UNDBLK(fmt, ...) printf("\033[4;30m" fmt "\033[0m", ##__VA_ARGS__);
#define UNDRED(fmt, ...) printf("\033[4;31m" fmt "\033[0m", ##__VA_ARGS__);
#define UNDGRN(fmt, ...) printf("\033[4;32m" fmt "\033[0m", ##__VA_ARGS__);
#define UNDYLW(fmt, ...) printf("\033[4;33m" fmt "\033[0m", ##__VA_ARGS__);
#define UNDLUN(fmt, ...) printf("\033[4;34m" fmt "\033[0m", ##__VA_ARGS__);
#define UNDPUR(fmt, ...) printf("\033[4;35m" fmt "\033[0m", ##__VA_ARGS__);
#define UNDCYN(fmt, ...) printf("\033[4;36m" fmt "\033[0m", ##__VA_ARGS__);
#define UNDWHT(fmt, ...) printf("\033[4;37m" fmt "\033[0m", ##__VA_ARGS__);

#define BAKBLK(fmt, ...) printf("\033[0;40m" fmt "\033[0m", ##__VA_ARGS__);
#define BAKRED(fmt, ...) printf("\033[0;41m" fmt "\033[0m", ##__VA_ARGS__);
#define BAKGRN(fmt, ...) printf("\033[0;42m" fmt "\033[0m", ##__VA_ARGS__);
#define BAKYLW(fmt, ...) printf("\033[0;43m" fmt "\033[0m", ##__VA_ARGS__);
#define BAKLUN(fmt, ...) printf("\033[0;44m" fmt "\033[0m", ##__VA_ARGS__);
#define BAKPUR(fmt, ...) printf("\033[0;45m" fmt "\033[0m", ##__VA_ARGS__);
#define BAKCYN(fmt, ...) printf("\033[0;46m" fmt "\033[0m", ##__VA_ARGS__);
#define BAKWHT(fmt, ...) printf("\033[0;47m" fmt "\033[0m", ##__VA_ARGS__);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif // COLORP_H