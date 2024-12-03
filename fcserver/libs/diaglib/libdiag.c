#include "libdiag.h"
#include "libmutex.h"

#include <execinfo.h>
#include <glob.h>
#include <utmp.h>

static mutex_t g_diag_mutex;
static int g_diag_log_maxsize = 4 * 1024 * 1024;

static char* g_diag_cfgfile = NULL;
static char* g_diag_logfile = NULL;
static char* g_diag_logname = NULL;

static int g_diag_foreground = 0;
static int g_diag_status = DIAG_ENABLE;
static int g_diag_level = DIAG_LEVEL_DEBUG;

static char* log_level_string(int level)
{
    switch (level)
    {
        case DIAG_LEVEL_EMERG:
            return "G";
        case DIAG_LEVEL_ERROR:
            return "E";
        case DIAG_LEVEL_WARNING:
            return "W";
        case DIAG_LEVEL_INFO:
            return "I";
        case DIAG_LEVEL_DEBUG:
            return "D";
        case DIAG_LEVEL_VERBOSE:
            return "V";
        default:
            return "-";
    }
}

void diag_backtrace(void)
{
    int i;
    int size;
    char** strings;
    void* frames[100];

    size = backtrace(frames, ARRAYSIZE(frames));
    if (size > 1)
    { /* skip the frame diag_backtrace itself. */
        strings = backtrace_symbols(&frames[1], size - 1);
        if (strings == NULL)
        {
            DIAG_ERROR("get backtrace symbols failed: %m\n");
            return;
        }

        DIAG_ERROR("total %d frames:\n", size - 1);
        for (i = 0; i < size - 1; i++)
        {
            DIAG_ERROR("<%p> %s\n", frames[i + 1], strings[i]);
        }

        free(strings);
    }
}

int diag_begin(diag_time_t* time)
{
    gettimeofday(&time->begin, NULL);
    return 0;
}

int diag_end(diag_time_t* time)
{
    gettimeofday(&time->end, NULL);
    return 0;
}

float diag_time(diag_time_t* time)
{
    int nsec;
    struct timeval diff;

    if (time->end.tv_usec < time->begin.tv_usec)
    {
        nsec = (time->begin.tv_usec - time->end.tv_usec) / 1000000 + 1;
        time->begin.tv_usec -= 1000000 * nsec;
        time->begin.tv_sec += nsec;
    }
    if (time->end.tv_usec - time->begin.tv_usec > 1000000)
    {
        nsec = (time->end.tv_usec - time->begin.tv_usec) / 1000000;
        time->begin.tv_usec += 1000000 * nsec;
        time->begin.tv_sec -= nsec;
    }

    diff.tv_sec = time->end.tv_sec - time->begin.tv_sec;
    diff.tv_usec = time->end.tv_usec - time->begin.tv_usec;

    time->used = (float)diff.tv_sec + (float)diff.tv_usec / 1000000;

    return time->used;
}

void diag_rotate(void)
{
    int len = 0;
    struct stat fs;
    char buffer[4096] = {
        0,
    };
    char tmpfile[64] = {
        0,
    };

    if (g_diag_logfile == NULL)
    {
        return;
    }

    if (stat(g_diag_logfile, &fs) == 0)
    {
        if (fs.st_size < g_diag_log_maxsize)
        {
            return;
        }
    }
    else
    {
        return;
    }

    FILE* logfp = fopen(g_diag_logfile, "r");
    if (logfp == NULL)
    {
        return;
    }

    snprintf(tmpfile, sizeof(tmpfile), "/tmp/%s.log-XXXXXX", g_diag_logname);
    int outfd = mkstemp(tmpfile);
    FILE* outfp = fdopen(outfd, "w");
    if (logfp == NULL)
    {
        fclose(logfp);
        return;
    }

    // keep the first messages after rotate.
    len = fread(buffer, 1, sizeof(buffer), logfp);
    if (len > 0)
    {
        if (fwrite(buffer, 1, len, outfp) != len)
        {
            fclose(outfp);
            fclose(logfp);
            unlink(tmpfile);
            return;
        }
    }

    fprintf(outfp, "\n......\n");

    // rorate the old messages.
    fseek(logfp, fs.st_size - (g_diag_log_maxsize >> 2), SEEK_SET);

    len = fread(buffer, 1, sizeof(buffer), logfp);
    while (len > 0)
    {
        if (fwrite(buffer, 1, len, outfp) != len)
        {
            fclose(outfp);
            fclose(logfp);
            unlink(tmpfile);
            return;
        }

        len = fread(buffer, 1, sizeof(buffer), logfp);
    }

    fclose(outfp);
    fclose(logfp);

    if (vasystem("mv %s %s", tmpfile, g_diag_logfile) < 0)
    {
        unlink(tmpfile);
        return;
    }

    sync();
    return;
}

/*
 * send a diag message to everybody's terminal.
 */
int diag_wallmsg(char* msg)
{
    FILE* fp;
    struct utmp* ut;
    char line[1024] = {
        0,
    };

    if (msg == NULL || msg[0] == '\0')
    {
        return 0;
    }

    setutent();
    while ((ut = getutent()) != NULL)
    {
        if (ut->ut_type != USER_PROCESS)
            continue;

        snprintf(line, sizeof(line), "/dev/%s", ut->ut_line);

        fp = fopen(line, "w");
        if (fp)
        {
            fputs(msg, fp);
            fclose(fp);
        }
    }
    endutent();

    return 0;
}

int diag_wall(char* fmt, ...)
{
    va_list valist;
    char msg[1024] = {
        0,
    };

    va_start(valist, fmt);
    vsnprintf(msg, sizeof(msg), fmt, valist);
    va_end(valist);

    diag_wallmsg(msg);
    return 0;
}

int diag(int level, char* fmt, ...)
{
    FILE* logfp;
    time_t timep;
    va_list valist;
    int old_errno = errno;
    char timestamp[32] = {
        0,
    };

    if (g_diag_foreground || g_diag_logfile == NULL)
    {
        va_start(valist, fmt);
        vprintf(fmt, valist);
        va_end(valist);
        return 0;
    }

    if (g_diag_cfgfile)
    {
        if (access(g_diag_cfgfile, F_OK) == 0)
        {
            FILE* fp = fopen(g_diag_cfgfile, "r");
            if (fp)
            {
                fscanf(fp, "%d", &g_diag_level);
                fclose(fp);
            }
            unlink(g_diag_cfgfile);
        }
    }

    if (g_diag_status == DIAG_DISABLE || level > g_diag_level)
    {
        return 0;
    }

    mutex_lock(&g_diag_mutex);
    diag_rotate();

    logfp = fopen(g_diag_logfile, "a+");
    if (logfp == NULL)
    {
        mutex_unlock(&g_diag_mutex);
        return -ENOENT;
    }

    fcntl(fileno(logfp), F_SETFD, FD_CLOEXEC);
    setvbuf(logfp, NULL, _IONBF, 0);

    time(&timep);
    strftime(timestamp, sizeof(timestamp), "%F %T", localtime(&timep));
    fprintf(logfp, "%s [%s] ", timestamp, log_level_string(level));

    errno = old_errno;
    va_start(valist, fmt);
    vfprintf(logfp, fmt, valist);
    va_end(valist);
    fclose(logfp);

    mutex_unlock(&g_diag_mutex);
    errno = old_errno;
    return 0;
}

int diag_memory(int level, void* mem, int size, char* fmt, ...)
{
    int i;
    int bpr = 64;
    int rowid = 0;
    FILE* logfp;
    va_list valist;
    uint8_t* data = (uint8_t*)mem;
    int old_errno = errno;

    if (g_diag_status == DIAG_DISABLE || level > g_diag_level)
    {
        return 0;
    }

    mutex_lock(&g_diag_mutex);
    diag_rotate();

    if (g_diag_logfile)
    {
        logfp = fopen(g_diag_logfile, "a+");
        if (logfp == NULL)
        {
            mutex_unlock(&g_diag_mutex);
            return -ENOENT;
        }

        fcntl(fileno(logfp), F_SETFD, FD_CLOEXEC);
        setvbuf(logfp, NULL, _IONBF, 0);
    }
    else
    {
        logfp = stderr;
    }

    errno = old_errno;
    va_start(valist, fmt);
    vfprintf(logfp, fmt, valist);
    va_end(valist);

    fprintf(logfp, "memory <%p> [%d]:\n", data, size);
    for (i = 0; i < size; i++)
    {
        if (i % bpr == 0)
        {
            fprintf(logfp, "%04X: ", rowid);
        }

        fprintf(logfp, "%02X", data[i]);
        if (i % 8 == 7)
        {
            fprintf(logfp, " ");
        }

        if (i % bpr == (bpr - 1))
        {
            fprintf(logfp, "\n");
            rowid++;
        }
        else if (i > 0 && i == size - 1)
        {
            fprintf(logfp, "\n");
        }
    }
    fprintf(logfp, "\n");
    if (logfp != stderr)
        fclose(logfp);

    mutex_unlock(&g_diag_mutex);
    errno = old_errno;
    return 0;
}

int diag_status_set(int status)
{
    int old_status = g_diag_status;

    if (status == DIAG_ENABLE)
    {
        g_diag_status = DIAG_ENABLE;
    }
    else if (status == DIAG_DISABLE)
    {
        g_diag_status = DIAG_DISABLE;
    }

    return old_status;
}

int diag_level_set(int level)
{
    int old_level = g_diag_level;

    if (level >= DIAG_LEVEL_EMERG && level <= DIAG_LEVEL_VERBOSE)
    {
        g_diag_level = level;
    }

    return old_level;
}

int diag_foreground_set(int foreground)
{
    g_diag_foreground = foreground;
    return 0;
}

int diag_restore(char* logname)
{
    int ret;
    int idx = 0;
    glob_t globbuf;
    char pattern[1024] = {
        0,
    };

    snprintf(pattern, sizeof(pattern), "%s/%s.log*", DIAG_ROOT_DIR, logname);

    globbuf.gl_offs = 0;
    globbuf.gl_pathc = 0;
    ret = glob(pattern, 0, NULL, &globbuf);
    if (ret == 0)
    {
        char* p = strrchr(globbuf.gl_pathv[globbuf.gl_pathc - 1], '.');
        if (p)
        {
            idx = strtol(p + 1, NULL, 10);
        }

        if (globbuf.gl_pathc > 50)
        {
            vasystem("rm -rf %s 1>/dev/null 2>&1", globbuf.gl_pathv[0]);
        }
    }

    if (access(g_diag_logfile, F_OK) == 0)
    {
        vasystem("mv %s/%s.log %s/%s.log.%02d 1>/dev/null 2>&1; sync",
                 DIAG_ROOT_DIR, logname, DIAG_ROOT_DIR, logname, idx + 1);
    }

    globfree(&globbuf);
    return 0;
}

int diag_init(char* logname)
{
    mutex_init(&g_diag_mutex);

    vasystem("mkdir -p %s", DIAG_ROOT_DIR);

    if (logname)
    {
        char* p = strrchr(logname, '/');
        if (p)
        {
            logname = p + 1;
        }
    }

    if (logname == NULL || logname[0] == '\0')
    {
        g_diag_logname = NULL;
        g_diag_logfile = NULL;
        return 0;
    }

    g_diag_cfgfile =
        strappendfmt(&g_diag_cfgfile, "%s/%s.cfg", DIAG_ROOT_DIR, logname);
    g_diag_logfile =
        strappendfmt(&g_diag_logfile, "%s/%s.log", DIAG_ROOT_DIR, logname);
    g_diag_logname = strdup(logname);

    diag_restore(logname);
    return 0;
}

void diag_fini(void)
{
    free(g_diag_cfgfile);
    g_diag_cfgfile = NULL;
    free(g_diag_logfile);
    g_diag_logfile = NULL;
    free(g_diag_logname);
    g_diag_logname = NULL;
    mutex_destroy(&g_diag_mutex);
}
