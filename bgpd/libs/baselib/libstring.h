#ifndef _LIBSTRING_H_
#define _LIBSTRING_H_

#include "libtypes.h"

#define ANSI_COLOR_RESET        "\x1b[0m"

#define ANSI_COLOR_BRIGHT       "\x1b[1m"
#define ANSI_COLOR_DIM          "\x1b[2m"
#define ANSI_COLOR_UNDERLINE    "\x1b[4m"
#define ANSI_COLOR_BLINK        "\x1b[5m"
#define ANSI_COLOR_REVERSE      "\x1b[7m"
#define ANSI_COLOR_HIDDEN       "\x1b[8m"

#define ANSI_COLOR_BLACK        "\x1b[30m"
#define ANSI_COLOR_RED          "\x1b[31m"
#define ANSI_COLOR_GREEN        "\x1b[32m"
#define ANSI_COLOR_YELLOW       "\x1b[33m"
#define ANSI_COLOR_BLUE         "\x1b[34m"
#define ANSI_COLOR_MAGENTA      "\x1b[35m"
#define ANSI_COLOR_CYAN         "\x1b[36m"
#define ANSI_COLOR_WHITE        "\x1b[37m"

#define ANSI_BGCOLOR_BLACK      "\x1b[40m"
#define ANSI_BGCOLOR_RED        "\x1b[41m"
#define ANSI_BGCOLOR_GREEN      "\x1b[42m"
#define ANSI_BGCOLOR_YELLOW     "\x1b[43m"
#define ANSI_BGCOLOR_BLUE       "\x1b[44m"
#define ANSI_BGCOLOR_MAGENTA    "\x1b[45m"
#define ANSI_BGCOLOR_CYAN       "\x1b[46m"
#define ANSI_BGCOLOR_WHITE      "\x1b[47m"

#define BLACKFMT(fmt) ANSI_COLOR_BLACK fmt ANSI_COLOR_RESET
#define REDFMT(fmt) ANSI_COLOR_RED fmt ANSI_COLOR_RESET
#define GREENFMT(fmt) ANSI_COLOR_GREEN fmt ANSI_COLOR_RESET
#define YELLOWFMT(fmt) ANSI_COLOR_YELLOW fmt ANSI_COLOR_RESET
#define BLUEFMT(fmt) ANSI_COLOR_BLUE fmt ANSI_COLOR_RESET
#define MAGENTAFMT(fmt) ANSI_COLOR_MAGENTA fmt ANSI_COLOR_RESET
#define CYANFMT(fmt) ANSI_COLOR_CYAN fmt ANSI_COLOR_RESET
#define BLINKFMT(fmt) ANSI_COLOR_BLINK fmt ANSI_COLOR_RESET

extern char hexcodechar(char c);
extern char hexcharcode(char x);

extern char *strtolower(char *str);
extern char *strtoupper(char *str);
extern char *capitalize(char *word);
extern char *strrtrim(char *str, char *trim);
extern char *strltrim(char *str, char *trim);
extern char *strtrim(char *str, char *trim);
extern char *stripwhite(char *str);
extern char *strprintify(char *str);
extern char *substring(char *s, int b, int e);
extern char *strprepend(char **dst, char *str);
extern char *strprependchar(char **dst, char c);
extern char *strprependfmt(char **dst, char *fmt, ...);
extern char *strappend(char **dst, char *str);
extern char *strappendchar(char **dst, char c);
extern char *strappendfmt(char **dst, char *fmt, ...);
extern char *strappendstdout(char **dst, char *cmd);
extern char *strappendstdoutvargs(char **dst, char *fmt, ...);
extern char *strappendrange(char **t, char *s, int b, int e);
extern char *strappendmem(char **dst, unsigned char *buf, int len);
extern char *strmixer(char *arg, ...);
extern char *strescapesqlite3(char *str);
extern char *strescapexml(char *str);
extern char *strescapejson(char *str);
extern uint32_t strbkdrhash(char *str, uint32_t initial);
extern uint32_t membkdrhash(void *mem, int size, uint32_t initial);
extern int strprefixcmp(char *str, char *prefix);
extern int strsuffixcmp(char *str, char *suffix);
extern int vasystem(char *fmt, ...);

extern int parse_int(char *arg, var_int_t *result);
extern int parse_uint(char *arg, var_uint_t *result);
extern int parse_u64(char *arg, var_uint64_t *result);
extern int parse_u16(char *arg, var_uint16_t *result);
extern int parse_u8(char *arg, var_uint8_t *result);
extern int parse_hex(char *arg, unsigned int *result);
extern int parse_time(char *arg, var_time_t *result);
extern int parse_datetime(char *arg, var_datetime_t *result);
extern int parse_boolean(char *arg, var_boolean_t *result);
extern int parse_string(char *arg, var_string_t *result);
extern int parse_strbuf(char *arg, var_strbuf_t *result);
extern int parse_float(char *arg, var_float_t *result);
extern int parse_double(char *arg, var_double_t *result);
extern int parse_complex(char *arg, var_complex_t *result);
extern int parse_range(char *arg, var_range_t *result);
extern int parse_ethaddr(char *arg, var_ethaddr_t *result);
extern int parse_fcport(char *arg, int *result);
extern int parse_fcspeed(char *arg, int *result);
extern int parse_iscsiport(char *arg, int *result);
extern int parse_wwnn(char *arg, var_wwnn_t *result);
extern int parse_ipaddr4(char *arg, var_ipaddr4_t *result);
extern int parse_cidraddr4(char *arg, var_cidraddr4_t *result);
extern int parse_ipaddr6(char *arg, var_ipaddr6_t *result);
extern int parse_cidraddr6(char *arg, var_cidraddr6_t *result);
extern int parse_enc_mode(char *arg, var_int_t *result);

extern char *format_datetime(var_datetime_t *input, char *fmtbuf, int size);
extern char *format_cidraddr4(var_cidraddr4_t *input, char *fmtbuf, int size);

extern char *build_argv(int argc, char **argv, int *msglen);
extern char *build_argcv(int argc, char **argv, int *msglen);
extern int parse_argcv(char *input, int length, char ***argv);

extern int parse_wordlist(char *line, char *delimiter, char ***wordlist);
extern void free_wordlist(int n, char **wordlist);

extern int parse_multi_int(char *arg, var_multi_int_t *result);
extern int parse_multi_uint(char *arg, var_multi_uint_t *result);
extern int parse_multi_float(char *arg, var_multi_float_t *result);
extern int parse_multi_double(char *arg, var_multi_double_t *result);
extern int parse_multi_range(char *arg, var_multi_range_t *result);

extern int parse_dirname(char *path, char **pdir);
extern int parse_basename(char *path, char **pbase);
extern int parse_dirbasename(char *path, char **pdir, char **pbase);
extern int parse_realname(char *path, char **pdir, char **preal, char **pext);
extern int parse_url(char *url, char **proto, char **domain);

extern void memdump(unsigned char *buf, int len, int bpr);
extern int memparse(char *arg, unsigned char **buf);

extern int strnrep(char *dst, char *fmt, char *msg, int n);

#endif
