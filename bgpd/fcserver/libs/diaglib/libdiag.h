#ifndef LIBDIAG_H
#define LIBDIAG_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "libtypes.h"
#include "libstring.h"

enum {
    DIAG_LEVEL_EMERG = 0,
    DIAG_LEVEL_ERROR = 1,
    DIAG_LEVEL_WARNING = 2,
    DIAG_LEVEL_INFO = 3,
    DIAG_LEVEL_DEBUG = 4,
    DIAG_LEVEL_VERBOSE = 5,

    DIAG_LEVEL_MAX
};

#define DIAG_ENABLE 1
#define DIAG_DISABLE 0

#define DIAG_ROOT_DIR "/opt/log"

#ifndef PRJ_SUPPORT_DEBUG
#define DIAG_ASSERT(exp)
#define DIAG_HERE()
#define DIAG_PRINT(fmt, args...)
#define DIAG_EMERG(fmt, args...) diag(DIAG_LEVEL_EMERG, fmt, ##args)
#define DIAG_ERROR(fmt, args...) diag(DIAG_LEVEL_ERROR, fmt, ##args)
#define DIAG_WARNING(fmt, args...) diag(DIAG_LEVEL_WARNING, fmt, ##args)
#define DIAG_INFO(fmt, args...) diag(DIAG_LEVEL_INFO, fmt, ##args)
#define DIAG_DEBUG(fmt, args...) diag(DIAG_LEVEL_DEBUG, fmt, ##args)
#define DIAG_VERBOSE(fmt, args...) diag(DIAG_LEVEL_VERBOSE, fmt, ##args)
#define DIAG_WALL(fmt, args...) diag(DIAG_LEVEL_DEBUG, fmt, ##args); diag_wall(fmt, ##args)
#define DIAG_MEMORY(mem, size, fmt, args...)
#else
#define DIAG_ASSERT(exp) \
do { \
    if (unlikely(!(exp))) { \
        diag(DIAG_LEVEL_ERROR, "[%04d@%s]Assertion failed: %s\n", __LINE__, __func__, #exp); \
        diag_backtrace(); \
        fflush(stderr); \
        abort(); \
    } \
} while (0)
#define DIAG_HERE() diag(DIAG_LEVEL_DEBUG, "[%04d@%s]\n", __LINE__, __func__)
#define DIAG_PRINT(fmt, args...) diag(DIAG_LEVEL_DEBUG, "[%04d@%s]"fmt, __LINE__, __func__, ##args)
#define DIAG_EMERG(fmt, args...) diag(DIAG_LEVEL_EMERG, BLINKFMT("[%04d@%s]"fmt), __LINE__, __func__, ##args)
#define DIAG_ERROR(fmt, args...) diag(DIAG_LEVEL_ERROR, REDFMT("[%04d@%s]"fmt), __LINE__, __func__, ##args)
#define DIAG_WARNING(fmt, args...) diag(DIAG_LEVEL_WARNING, YELLOWFMT("[%04d@%s]"fmt), __LINE__, __func__, ##args)
#define DIAG_INFO(fmt, args...) diag(DIAG_LEVEL_INFO, "[%04d@%s]"fmt, __LINE__, __func__, ##args)
#define DIAG_DEBUG(fmt, args...) diag(DIAG_LEVEL_DEBUG, "[%04d@%s]"fmt, __LINE__, __func__, ##args)
#define DIAG_VERBOSE(fmt, args...) diag(DIAG_LEVEL_VERBOSE, "[%04d@%s]"fmt, __LINE__, __func__, ##args)
#define DIAG_WALL(fmt, args...) diag(DIAG_LEVEL_DEBUG, "[%04d@%s]"fmt, __LINE__, __func__, ##args); diag_wall("[%04d@%s]"fmt, __LINE__, __func__, ##args)
#define DIAG_MEMORY(mem, size, fmt, args...) diag_memory(DIAG_LEVEL_DEBUG, mem, size, "[%04d@%s]"fmt, __LINE__, __func__, ##args)
#endif

#ifndef PRJ_SUPPORT_DDEBUG
#define DIAG_DPRINT(fmt, args...)
#else
#define DIAG_DPRINT(fmt, args...) diag(DIAG_LEVEL_DEBUG, "[%04d@%s]"fmt, __LINE__, __func__, ##args)
#endif

typedef struct diag_time_st {
    struct timeval begin;
    struct timeval end;
    float used;
} diag_time_t;

extern int diag_begin(diag_time_t *time);
extern int diag_end(diag_time_t *time);
extern float diag_time(diag_time_t *time);

extern void diag_backtrace(void);
extern void diag_rotate(void);
extern int diag_wallmsg(char *msg);
extern int diag_wall(char *fmt, ...);
extern int diag(int level, char *fmt, ...);
extern int diag_memory(int level, void *mem, int size, char *fmt, ...);
extern int diag_status_set(int status);
extern int diag_level_set(int level);
extern int diag_foreground_set(int foreground);
extern int diag_init(char *logname);
extern void diag_fini(void);

#endif
