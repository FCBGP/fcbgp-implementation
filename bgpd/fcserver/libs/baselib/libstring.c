#include "libstring.h"

#include <arpa/inet.h>

char hexcodechar(char c)
{
    char hexpool[] = "0123456789abcdef";
    if (c >= 0x10) {
        return 0x10;
    }

    return hexpool[c & 0x0F];
}

char hexcharcode(char x)
{
    if (x >= '0' && x <= '9')
        return x - '0';
    if (x >= 'a' && x <= 'f')
        return x - 'a' + 10;
    if (x >= 'A' && x <= 'F')
        return x - 'A' + 10;
    return 0x10;
}

char *strtolower(char *str)
{
    char *p;

    for (p=str; *p; p++) {
        *p = tolower((int)*p);
    }

    return str;
}

char *strtoupper(char *str)
{
    char *p;

    for (p=str; *p; p++) {
        *p = toupper((int)*p);
    }

    return str;
}

char *capitalize(char *word)
{
    char *p = word;

    *p = toupper((int)*p);
    p++;

    while (*p) {
        *p = tolower((int)*p);
        p++;
    }

    return word;
}

char *strrtrim(char *str, char *trim)
{
    char *end;
    char *whitespaces = " \t\r\n";

    trim = trim ? : whitespaces;

    end = str + strlen(str);
    while (end-- > str) {
        if (!strchr(trim, *end))
            return str;
        *end = '\0';
    }

    return str;
}

/*
 * beware the leaking memory when use the return pointer!
 */
char *strltrim(char *str, char *trim)
{
    char *whitespaces = " \t\r\n";

    trim = trim ? : whitespaces;

    while (*str) {
        if (!strchr(trim, *str))
            return str;
        ++str;
    }

    return str;
}

char *strtrim(char *str, char *trim)
{
    return strltrim(strrtrim(str, trim), trim);
}

char *stripwhite(char *str)
{
    return strtrim(str, NULL);
}

char *strprintify(char *str)
{
    char *p;

    for (p=str; *p; p++) {
        if (!isprint(*p) || isspace(*p)) {
            *p = '.';
        }
    }

    return str;
}

char *substring(char *s, int b, int e)
{
    char *p = s + b;

    if (b > e) {
        return NULL;
    }

    return strndup(p, e - b + 1);
}

char *strprepend(char **dst, char *str)
{
    char *oldstr;
    char *newstr;

    if (dst == NULL) {
        return NULL;
    }

    if (str == NULL) {
        return *dst;
    }

    if (str[0] == '\0') {
        if (*dst == NULL) {
            return strdup("");
        } else {
            return *dst;
        }
    }

    oldstr = *dst;
    if (oldstr) {
        newstr = malloc(strlen(oldstr) + strlen(str) + 1);
        if (newstr == NULL) {
            return NULL;
        }

        newstr[0] = '\0';
        strcat(newstr, str);
        strcat(newstr, oldstr);
    } else {
        newstr = malloc(strlen(str) + 1);
        if (newstr == NULL) {
            return NULL;
        }

        newstr[0] = '\0';
        strcat(newstr, str);
    }

    free(oldstr);
    *dst = newstr;
    return newstr;
}

char *strprependchar(char **dst, char c)
{
    char s[2] = { c, '\0' };

    return strprepend(dst, s);
}

char *strprependfmt(char **dst, char *fmt, ...)
{
    int ret;
    va_list params;
    char *result, *head = NULL;

    va_start(params, fmt);
    ret = vasprintf(&head, fmt, params);
    va_end(params);

    if (ret < 0)
        return NULL;

    result = strprepend(dst, head);

    free(head);
    return result;
}

char *strappend(char **dst, char *str)
{
    char *oldstr;
    char *newstr;

    if (dst == NULL) {
        return NULL;
    }

    if (str == NULL) {
        return *dst;
    }

    if (str[0] == '\0') {
        if (*dst == NULL) {
            return strdup("");
        } else {
            return *dst;
        }
    }

    oldstr = (*dst);
    if (oldstr) {
        newstr = malloc(strlen(oldstr) + strlen(str) + 1);
        if (newstr == NULL) {
            return NULL;
        }

        newstr[0] = '\0';
        strcat(newstr, oldstr);
        strcat(newstr, str);
    } else {
        newstr = malloc(strlen(str) + 1);
        if (newstr == NULL) {
            return NULL;
        }

        newstr[0] = '\0';
        strcat(newstr, str);
    }

    free(oldstr);
    *dst = newstr;
    return newstr;
}

char *strappendchar(char **dst, char c)
{
    char s[2] = {c, '\0'};

    return strappend(dst, s);
}

char *strappendfmt(char **dst, char *fmt, ...)
{
    int ret;
    va_list params;
    char *result, *rear = NULL;

    va_start(params, fmt);
    ret = vasprintf(&rear, fmt, params);
    va_end(params);

    if (ret < 0)
        return NULL;

    result = strappend(dst, rear);

    free(rear);
    return result;
}

char *strappendstdout(char **dst, char *cmd)
{
    size_t len = 0;
    FILE *f = NULL;
    char *line = NULL;
    char *result = NULL;

    if (!(f = popen(cmd, "r"))) {
        return result;
    }

    while (getline(&line, &len, f) != -1) {
        result = strappend(dst, line);
    }

    free(line);
    pclose(f);
    return result;
}

char *strappendstdoutvargs(char **dst, char *fmt, ...)
{
    va_list params;
    char *cmd = NULL;
    char *result = NULL;

    va_start(params, fmt);
    vasprintf(&cmd, fmt, params);
    va_end(params);

    result = strappendstdout(dst, cmd);

    free(cmd);
    return result;
}

char *strappendrange(char **t, char *s, int b, int e)
{
    char *subs = substring(s, b, e);
    char *result = strappend(t, subs);
    free(subs);
    return result;
}

char *strappendmem(char **dst, unsigned char *buf, int len)
{
    int i;
    char *result = NULL;

    for (i = 0; i < len; i++) {
        result = strappendfmt(dst, "%02X", buf[i]);
    }

    return result;
}

/*
 * Note: the variable parameter list must be end with NULL.
 */
char *strmixer(char *arg, ...)
{
    va_list params;
    char *p = arg, *dst = NULL;

    va_start(params, arg);
    while (p) {
        strappend(&dst, p);
        p = (char *) va_arg(params, char *);
    }
    va_end(params);

    return dst;
}

char *strescapesqlite3(char *str)
{
    char *p, *q = NULL;

    for (p=str; p && *p; p++) {
        if (*p == '\'') {
            strappendchar(&q, *p);
        }
        strappendchar(&q, *p);
    }

    return q;
}

char *strescapexml(char *str)
{
    char *p, *q = NULL;

    for (p=str; p && *p; p++) {
        if (*p == '<') {
            strappend(&q, "&lt;");
        } else if (*p == '>') {
            strappend(&q, "&gt;");
        } else if (*p == '&') {
            strappend(&q, "&amp;");
        } else if (*p == '"') {
            strappend(&q, "&quot;");
        } else if (*p == '\'') {
            strappend(&q, "&apos;");
        } else {
            strappendchar(&q, *p);
        }
    }

    return q;
}

char *strescapejson(char *str)
{
    char *p, *q = NULL;

    for (p=str; p && *p; p++) {
        if (*p == '"' || *p == '\\' || *p == '/') {
            strappendchar(&q, '\\');
            strappendchar(&q, *p);
        } else if (*p == '\b') {
            strappend(&q, "\\b");
        } else if (*p == '\f') {
            strappend(&q, "\\f");
        } else if (*p == '\n') {
            strappend(&q, "\\n");
        } else if (*p == '\r') {
            strappend(&q, "\\r");
        } else if (*p == '\t') {
            strappend(&q, "\\t");
        } else {
            strappendchar(&q, *p);
        }
    }

    return q;
}

/**
 * BKDR Hash Function
 */
uint32_t strbkdrhash(char *str, uint32_t initial)
{
    /* 31 131 1313 13131 131313 etc.. */
    uint32_t seed = 131;
    uint32_t hash = initial;
    uint8_t *ptr = (uint8_t *)str;

    while (*ptr) {
        hash = hash * seed + (*ptr++);
    }

    return hash;
}

uint32_t membkdrhash(void *mem, int size, uint32_t initial)
{
    int i;
    /* 31 131 1313 13131 131313 etc.. */
    uint32_t seed = 131;
    uint32_t hash = initial;
    uint8_t *ptr = (uint8_t *)mem;

    for (i=0; i<size; i++) {
        hash = hash * seed + ptr[i];
    }

    return hash;
}

int strprefixcmp(char *str, char *prefix)
{
    char *p, *q;

    if (!str || !prefix)
        return 1;

    for (p = prefix, q = str; *p; p++, q++) {
        if (*q == '\0')
            return 1;
        if (*p != *q)
            return 1;
    }

    return 0;
}

int strsuffixcmp(char *str, char *suffix)
{
    int n, m;
    char *p, *q;

    if (!str || !suffix)
        return 1;

    n = strlen(str);
    m = strlen(suffix);

    if (m > n)
        return 1;

    for (p = suffix + m - 1, q = str + n - 1; p >= suffix; p--, q--) {
        if (*p != *q)
            return 1;
    }

    return 0;
}

int vasystem(char *fmt, ...)
{
    int ret;
    va_list params;
    char *cmd = NULL;

    va_start(params, fmt);
    ret = vasprintf(&cmd, fmt, params);
    va_end(params);

    if (ret < 0)
        return -1;

    ret = system(cmd);

    free(cmd);
    return ret;
}

int parse_int(char *arg, var_int_t *result)
{
    long int val;
    int ret = -1;
    char *endptr = NULL;

    if (!arg || !result) {
        goto out;
    }

    errno = 0;
    val = strtol(arg, &endptr, 0);
    if (errno == EINVAL || errno == ERANGE || endptr == arg) {
        goto out;
    }

    if (*endptr != '\0') {
        goto out;
    }

    ret = 0;
    *result = val;
out:
    return ret;
}

int parse_uint(char *arg, var_uint_t *result)
{
    int ret = -1;
    char *endptr = NULL;
    unsigned long int val;

    if (!arg || !result) {
        goto out;
    }

    errno = 0;
    val = strtoul(arg, &endptr, 0);
    if (errno == EINVAL || errno == ERANGE || endptr == arg) {
        goto out;
    }

    if (*endptr != '\0') {
        goto out;
    }

    ret = 0;
    *result = val;
out:
    return ret;
}

int parse_u64(char *arg, var_uint64_t *result)
{
    int ret = -1;
    char *endptr = NULL;
    unsigned long long int val;

    if (!arg || !result) {
        goto out;
    }

    errno = 0;
    val = strtoull(arg, &endptr, 0);
    if (errno == EINVAL || errno == ERANGE || endptr == arg) {
        goto out;
    }

    if (*endptr != '\0') {
        goto out;
    }

    ret = 0;
    *result = val;
out:
    return ret;
}


int parse_u16(char *arg, var_uint16_t *result)
{
    int ret = -1;
    char *endptr = NULL;
    unsigned long int val;

    if (!arg || !result) {
        goto out;
    }

    errno = 0;
    val = strtoul(arg, &endptr, 0);
    if (errno == EINVAL || errno == ERANGE || endptr == arg) {
        goto out;
    }

    if (*endptr != '\0') {
        goto out;
    }

    if (val > UINT16_MAX) {
        goto out;
    }

    ret = 0;
    *result = val;
out:
    return ret;
}

int parse_u8(char *arg, var_uint8_t *result)
{
    int ret = -1;
    char *endptr = NULL;
    unsigned long int val;

    if (!arg || !result) {
        goto out;
    }

    errno = 0;
    val = strtoul(arg, &endptr, 0);
    if (errno == EINVAL || errno == ERANGE || endptr == arg) {
        goto out;
    }

    if (*endptr != '\0') {
        goto out;
    }

    if (val > UINT8_MAX) {
        goto out;
    }

    ret = 0;
    *result = val;
out:
    return ret;
}

int parse_hex(char *arg, unsigned int *result)
{
    int ret = -1;
    char *endptr = NULL;
    unsigned long int val;

    if (!arg || !result) {
        goto out;
    }

    val = strtoul(arg, &endptr, 16);
    if (errno == EINVAL || errno == ERANGE || endptr == arg) {
        goto out;
    }

    if (*endptr != '\0') {
        goto out;
    }

    ret = 0;
    *result = val;
out:
    return ret;
}

int parse_time(char *arg, var_time_t *result)
{
    int ret = -1;
    int hours, minutes, seconds;

    if (!arg || !result) {
        goto out;
    }

    if (sscanf(arg, "%d:%d:%d", &hours, &minutes, &seconds) != 3) {
        goto out;
    }

    if (hours > 60 || minutes > 60 || seconds > 60) {
        goto out;
    }

    *result = 3600 * hours + 60 * minutes + seconds;
    ret = 0;
out:
    return ret;
}

int parse_datetime(char *arg, var_datetime_t *result)
{
    int ret = -1;
    int year = 0, month = 0, day = 0;
    int hours = 0, minutes = 0, seconds = 0;

    if (!arg || !result) {
        goto out;
    }

    if (sscanf(arg, "%d-%d-%d %d:%d:%d", &year, &month, &day, &hours, &minutes, &seconds) != 6) {
        if (sscanf(arg, "%d-%d-%d", &year, &month, &day) != 3) {
            goto out;
        }
    }

    if (year < 0 || month < 0 || month > 12 || day < 0 ||day > 31) {
        goto out;
    }

    if (month == 2) {
        if ((year % 400) == 0 || ((year % 100) && (year % 4) == 0)) {
            if (day > 29) {
                goto out;
            }
        } else {
            if (day > 28) {
                goto out;
            }
        }
    }

    if (hours > 60 || minutes > 60 || seconds > 60) {
        goto out;
    }

    result->year = year;
    result->month = month;
    result->day = day;
    result->hour = hours;
    result->minute = minutes;
    result->second = seconds;
    ret = 0;
out:
    return ret;
}

char *format_datetime(var_datetime_t *input, char *fmtbuf, int size)
{
    int ret = -1;

    if (fmtbuf == NULL) {
        return NULL;
    }

    ret = snprintf(fmtbuf, size, "%d-%02d-%02d %02d:%02d:%02d",
            input->year, input->month, input->day,
            input->hour, input->minute, input->second);
    if (ret < 0) {
        return NULL;
    }

    return fmtbuf;
}

int parse_boolean(char *arg, var_boolean_t *result)
{
    int ret = -1;

    if (!arg || !result) {
        goto out;
    }

    if (!strcasecmp(arg, "true")
        || !strcasecmp(arg, "yes")
        || !strcasecmp(arg, "enable")
        || !strcasecmp(arg, "on")
        || !strcmp(arg, "1")) {
        *result = 1;
    } else if (!strcasecmp(arg, "false")
        || !strcasecmp(arg, "no")
        || !strcasecmp(arg, "disable")
        || !strcasecmp(arg, "off")
        || !strcmp(arg, "0")) {
        *result = 0;
    } else {
        goto out;
    }

    ret = 0;
out:
    return ret;
}

int parse_string(char *arg, var_string_t *result)
{
    int ret = -1;

    if (!arg || !result) {
        goto out;
    }

    *result = arg;
    ret = 0;
out:
    return ret;
}

int parse_strbuf(char *arg, var_strbuf_t *result)
{
    int ret = -1;

    if (!arg || !result) {
        goto out;
    }

    strncpy(result->strbuf, arg, sizeof(result->strbuf));
    ret = 0;
out:
    return ret;
}

int parse_float(char *arg, var_float_t *result)
{
    float val;
    int ret = -1;
    char *endptr = NULL;

    if (!arg || !result) {
        goto out;
    }

    errno = 0;
    val = strtof(arg, &endptr);
    if (errno == EINVAL || errno == ERANGE || endptr == arg) {
        goto out;
    }

    if (*endptr != '\0') {
        goto out;
    }

    ret = 0;
    *result = val;
out:
    return ret;
}

int parse_double(char *arg, var_double_t *result)
{
    double val;
    int ret = -1;
    char *endptr = NULL;

    if (!arg || !result) {
        goto out;
    }

    errno = 0;
    val = strtod(arg, &endptr);
    if (errno == EINVAL || errno == ERANGE || endptr == arg) {
        goto out;
    }

    if (*endptr != '\0') {
        goto out;
    }

    ret = 0;
    *result = val;
out:
    return ret;
}

int parse_complex(char *arg, var_complex_t * result)
{
    double val;
    char *p, *q = NULL;

    if (!arg || !result) {
        return -1;
    }

    p = arg;
    while (*p == ' ' || *p == '\t') {
        p++;
    }

    if (*p == '\0') {
        return -1;
    }

    errno = 0;
    if (*p == 'i') {
        val = strtod(p + 1, &q);
        if (errno == EINVAL || errno == ERANGE || q == p + 1) {
            return -1;
        }

        if (*q != '\0') {
            return -1;
        }

        result->image = 1.0;
        result->real = val;
        return 0;
    } else if (*p == '+' || *p == '-') {
        q = p + 1;
        if (*q == 'i') {
            if (*p == '+')
                result->image = 1.0;
            if (*p == '-')
                result->image = -1.0;

            q++;
            if (*q == '\0') {
                result->real = 0.0;
                return 0;
            } else {
                p = q;
                val = strtod(p, &q);
                if (errno == EINVAL || errno == ERANGE || q == p) {
                    return -1;
                }

                if (*q != '\0') {
                    return -1;
                }

                result->real = val;
                return 0;
            }
        } else if (*q == '\0') {
            return -1;
        }
    }

    val = strtod(p, &q);
    if (errno == EINVAL || errno == ERANGE || q == p) {
        return -1;
    }

    if (*q == '+' || *q == '-') {
        p = q + 1;
        if (*p == 'i') {
            if (*p == '+')
                result->image = 1.0;
            if (*p == '-')
                result->image = -1.0;

            p++;
            if (*p != '\0') {
                return -1;
            }

            result->real = val;
            return 0;
        }

        p = q;
        result->real = val;
        val = strtod(p, &q);
        if (errno == EINVAL || errno == ERANGE || q == p) {
            return -1;
        }

        if (*q != 'i') {
            return -1;
        }

        q++;
        if (*q != '\0') {
            return -1;
        }

        result->image = val;
        return 0;
    } else if (*q == 'i') {
        result->image = val;

        p = q + 1;
        if (*p == '\0') {
            result->real = 0.0;
            return 0;
        } else {
            val = strtod(p, &q);
            if (errno == EINVAL || errno == ERANGE || q == p) {
                return -1;
            }

            if (*q != '\0') {
                return -1;
            }

            result->real = val;
            return 0;
        }
    } else if (*q == '\0') {
        result->real = val;
        result->image = 0.0;
        return 0;
    } else {
        return -1;
    }

    return -1;
}

int parse_range(char *arg, var_range_t * result)
{
    int ret = -1;
    char *strike;
    char part[16] = { 0, };
    int32_t start, end;

    if (!arg || !result) {
        goto out;
    }

    strike = strchr(arg, '-');
    if (strike == NULL) {
        if (parse_int(arg, &start) < 0) {
            goto out;
        }

        result->end = result->start = start;
    } else {
        /*
         *at most 10 digits
         */
        if (strike - arg > 10) {
            goto out;
        }

        strncpy(part, arg, strike - arg);
        if (parse_int(part, &start) < 0) {
            goto out;
        }

        if (parse_int(strike + 1, &end) < 0) {
            goto out;
        }

        if (end < start) {
            goto out;
        }

        result->start = start;
        result->end = end;
    }

    ret = 0;
out:
    return ret;
}

int parse_fcport(char *arg, int *result)
{
    if (strcasecmp(arg, "fc0") == 0) {
        *result = 0;
    } else if (strcasecmp(arg, "fc1") == 0) {
        *result = 1;
    } else if (strcasecmp(arg, "fc2") == 0) {
        *result = 2;
    } else if (strcasecmp(arg, "fc3") == 0) {
        *result = 3;
    } else {
        return -1;
    }

    return 0;
}


int parse_fcspeed(char *arg, int *result)
{
    if (strcasecmp(arg, "1") == 0) {
        *result = 1;
    } else if (strcasecmp(arg, "2") == 0) {
        *result = 2;
    } else if (strcasecmp(arg, "4") == 0) {
        *result = 4;
    } else if (strcasecmp(arg, "8") == 0) {
        *result = 8;
    } else {
        return -1;
    }

    return 0;
}


int parse_iscsiport(char *arg, int *result)
{
    if (strcasecmp(arg, "xgbe0") == 0) {
        *result = 0;
    } else if (strcasecmp(arg, "xgbe1") == 0) {
        *result = 1;
    } else if (strcasecmp(arg, "xgbe2") == 0) {
        *result = 2;
    } else if (strcasecmp(arg, "xgbe3") == 0) {
        *result = 3;
    } else {
        return -1;
    }

    return 0;
}

int parse_ethaddr(char *arg, var_ethaddr_t * result)
{
    int ret = -1;

    if (!arg || !result) {
        goto out;
    }

    if (sscanf(arg, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
            &result->mac[0], &result->mac[1], &result->mac[2],
            &result->mac[3], &result->mac[4], &result->mac[5]) != 6) {
        goto out;
    }

    ret = 0;
out:
    return ret;
}

int parse_wwnn(char *arg, var_wwnn_t *result)
{
    int ret = -1;

    if (!arg || !result) {
        goto out;
    }

    if (sscanf(arg, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
            &result->wwnn[0], &result->wwnn[1], &result->wwnn[2], &result->wwnn[3],
            &result->wwnn[4], &result->wwnn[5], &result->wwnn[6], &result->wwnn[7]) != 8) {
        goto out;
    }

    ret = 0;
out:
    return ret;
}

int parse_ipaddr4(char *arg, var_ipaddr4_t * result)
{
    int ret = -1;
    struct in_addr ipv4;

    if (!arg || !result) {
        goto out;
    }

    if (inet_pton(AF_INET, arg, &ipv4) != 1) {
        goto out;
    }

    memcpy(result, &ipv4, sizeof(struct in_addr));
    ret = 0;
out:
    return ret;
}

int parse_cidraddr4(char *arg, var_cidraddr4_t * result)
{
    int ret = -1;
    char *slash = NULL;
    char part[INET_ADDRSTRLEN] = { 0, };

    if (!arg || !result) {
        goto out;
    }

    slash = strchr(arg, '/');
    if (slash == NULL) {
        goto out;
    }

    /*
     *at most INET_ADDRSTRLEN - 1=15 characters
     */
    if (slash - arg > INET_ADDRSTRLEN - 1) {
        goto out;
    }

    strncpy(part, arg, slash - arg);
    if (parse_ipaddr4(part, &result->ipaddr4)) {
        goto out;
    }

    if (parse_uint(slash + 1, &result->prefix)) {
        goto out;
    }

    if (result->prefix < 0 || result->prefix > 32) {
        goto out;
    }

    ret = 0;
out:
    return ret;
}

char *format_cidraddr4(var_cidraddr4_t *input, char *fmtbuf, int size)
{
    int ret = -1;

    if (fmtbuf == NULL) {
        return NULL;
    }

    ret = snprintf(fmtbuf, size, "%d.%d.%d.%d/%d",
            input->ipaddr4.u.addr8[0], input->ipaddr4.u.addr8[1],
            input->ipaddr4.u.addr8[2], input->ipaddr4.u.addr8[3],
            input->prefix);
    if (ret < 0) {
        return NULL;
    }

    return fmtbuf;
}

int parse_ipaddr6(char *arg, var_ipaddr6_t * result)
{
    int ret = -1;
    struct in6_addr ipv6;

    if (!arg || !result) {
        goto out;
    }

    if (inet_pton(AF_INET6, arg, &ipv6) != 1) {
        goto out;
    }

    memcpy(result, &ipv6, sizeof(struct in6_addr));
    ret = 0;
out:
    return ret;
}

int parse_cidraddr6(char *arg, var_cidraddr6_t * result)
{
    int ret = -1;
    char *slash = NULL;
    char part[INET6_ADDRSTRLEN] = { 0, };

    if (!arg || !result) {
        goto out;
    }

    slash = strchr(arg, '/');
    if (slash == NULL) {
        goto out;
    }

    /*
     *at most INET6_ADDRSTRLEN - 1=45 characters
     */
    if (slash - arg > INET6_ADDRSTRLEN - 1) {
        goto out;
    }

    strncpy(part, arg, slash - arg);
    if (parse_ipaddr6(part, &result->ipaddr6)) {
        goto out;
    }

    if (parse_uint(slash + 1, &result->prefix)) {
        goto out;
    }

    if (result->prefix < 0 || result->prefix > 128) {
        goto out;
    }

    ret = 0;
out:
    return ret;
}

char *build_argv(int argc, char **argv, int *msglen)
{
    int i;
    char *msg = NULL;
    char *nmsg = NULL;
    int len, size, offset, capacity;

    size = 128;
    msg = malloc(size);
    if (msg == NULL) {
        return NULL;
    }

    offset = 0; capacity = size - offset;
    for (i=0; i<argc; i++) {
        while (1) {
            len = snprintf(msg + offset, capacity, "%s", argv[i]);
            if (len < 0) {
                free(msg);
                return NULL;
            }

            if (len == capacity) {
                size = len + 1;
                capacity = size - offset;
            } else if (len > capacity) {
                size = size << 1;
                capacity = size - offset;
            } else {
                msg[offset + len] = '\0';
                offset += len + 1;
                capacity = size - offset;
                break;
            }

            nmsg = realloc(msg, size);
            if (nmsg == NULL) {
                free(msg);
                return NULL;
            }

            msg = nmsg;
        }
    }

    *msglen = offset;
    return msg;
}

char *build_argcv(int argc, char **argv, int *msglen)
{
    int i;
    char *msg = NULL;
    char *nmsg = NULL;
    int len, size, offset, capacity;

    size = 128;
    msg = malloc(size);
    if (msg == NULL) {
        return NULL;
    }

    offset = 0; capacity = size - offset;
    while (1) {
        len = snprintf(msg + offset, capacity, "%d", argc);
        if (len < 0) {
            free(msg);
            return NULL;
        }

        if (len == capacity) {
            size = len + 1;
            capacity = size - offset;
        } else if (len > capacity) {
            size = size << 1;
            capacity = size - offset;
        } else {
            msg[offset + len] = '\0';
            offset += len + 1;
            capacity = size - offset;
            break;
        }

        nmsg = realloc(msg, size);
        if (nmsg == NULL) {
            free(msg);
            return NULL;
        }

        msg = nmsg;
    }

    for (i=0; i<argc; i++) {
        while (1) {
            len = snprintf(msg + offset, capacity, "%s", argv[i]);
            if (len < 0) {
                free(msg);
                return NULL;
            }

            if (len == capacity) {
                size = len + 1;
                capacity = size - offset;
            } else if (len > capacity) {
                size = size << 1;
                capacity = size - offset;
            } else {
                msg[offset + len] = '\0';
                offset += len + 1;
                capacity = size - offset;
                break;
            }

            nmsg = realloc(msg, size);
            if (nmsg == NULL) {
                free(msg);
                return NULL;
            }

            msg = nmsg;
        }
    }

    *msglen = offset;
    return msg;
}

int parse_argcv(char *input, int length, char ***argv)
{
    int i;
    int argc = 0;
    int offset = 0;
    char *start = input;
    char **words = NULL;

    argc = strtol(start, NULL, 10);
    words = calloc(sizeof(char *), argc);
    if (words == NULL)
        return -1;

    offset = strlen(start) + 1;

    start = input + offset;
    for (i=0; i<argc; i++) {
        words[i] = start;
        offset += strlen(words[i]) + 1;
        if (offset >= length)
            break;
        start = input + offset;
    }

    *argv = words;
    return i + 1;
}

static char *parse_token(char **line, char *delimiter)
{
    char *start = NULL;
    char *end = NULL;
    char *cursor = NULL;
    char *token = NULL;

    for (cursor = (*line); *cursor && strchr(delimiter, *cursor); cursor++);

    if (*cursor == '"') {
        for (start = ++cursor; *cursor && *cursor != '"'; cursor++);
        if (*cursor == '"') {
            end = cursor;       /* not include end */
        } else {
            /** missing the end quote */
            return NULL;
        }
        token = strndup(start, end - start);
        *line = cursor + 1;
        return token;
    } else if (*cursor == '\'') {
        for (start = ++cursor; *cursor && *cursor != '\''; cursor++);
        if (*cursor == '\'') {
            end = cursor;       /* not include end */
        } else {
            /** missing the end quote */
            return NULL;
        }
        token = strndup(start, end - start);
        *line = cursor + 1;
        return token;
    } else if (*cursor == '\0') {
        return NULL;
    }

    start = cursor;
    while (*cursor) {
        if (strchr(delimiter, *cursor)) {
            if (*(cursor - 1) == '\\') {
                cursor++;
            } else {
                break;
            }
        } else {
            cursor++;
        }
    }
    end = cursor;

    token = strndup(start, end - start);
    *line = cursor;

    return token;
}

/**
 *@brief split the string into multiple tokens.
 *
 * each char in delimiter will be taken as a separator.
 * you can use a backsplash to escape the delimiters or
 * use the quotes to wrap the delimiters.
 *
 * you need to free the wordlist and each word in the wordlist.
 */
int parse_wordlist(char *line, char *delimiter, char ***wordlist)
{
    int n = 0;
    char *start = line;
    char **list = NULL;
    char *token = NULL;

    if (line == NULL || line[0] == '\0' || delimiter == NULL || delimiter[0] == '\0') {
        goto done;
    }

    list = malloc(strlen(line) * sizeof(char *));
    if (list == NULL) {
        goto done;
    }

    token = parse_token(&start, delimiter);
    while (token) {
        //printf("token[%d]=[%s]\n", n, token);
        list[n++] = token;
        token = parse_token(&start, delimiter);
    }

    if (n == 0) {
        free(list);
        goto done;
    }

    *wordlist = list;
done:
    return n;
}

void free_wordlist(int n, char **wordlist)
{
    int i;

    if (wordlist) {
        for (i = 0; i < n; i++) {
            free(wordlist[i]);
        }
        free(wordlist);
    }
}

int parse_multi_int(char *arg, var_multi_int_t *result)
{
    int ret;
    int i, n;
    char **wordlist;

    n = parse_wordlist(arg, ",", &wordlist);
    if (n <= 0)
        return -1;

    if (n >= MULTI_VALUE_MAX) {
        printf("you input %d values, should be less than %d\n", n, MULTI_VALUE_MAX);
        free_wordlist(n, wordlist);
        return -1;
    }

    result->n = n;
    for (i=0; i<n; i++) {
        ret = parse_int(wordlist[i], result->v + i);
        if (ret < 0) {
            free_wordlist(n, wordlist);
            return ret;
        }
    }

    free_wordlist(n, wordlist);
    return 0;
}

int parse_multi_uint(char *arg, var_multi_uint_t *result)
{
    int ret;
    int i, n;
    char **wordlist;

    n = parse_wordlist(arg, ",", &wordlist);
    if (n <= 0)
        return -1;

    if (n >= MULTI_VALUE_MAX) {
        printf("you input %d values, should be less than %d\n", n, MULTI_VALUE_MAX);
        free_wordlist(n, wordlist);
        return -1;
    }

    result->n = n;
    for (i=0; i<n; i++) {
        ret = parse_uint(wordlist[i], result->v + i);
        if (ret < 0) {
            free_wordlist(n, wordlist);
            return ret;
        }
    }

    free_wordlist(n, wordlist);
    return 0;
}

int parse_multi_float(char *arg, var_multi_float_t *result)
{
    int ret;
    int i, n;
    char **wordlist;

    n = parse_wordlist(arg, ",", &wordlist);
    if (n <= 0)
        return -1;

    if (n >= MULTI_VALUE_MAX) {
        printf("you input %d values, should be less than %d\n", n, MULTI_VALUE_MAX);
        free_wordlist(n, wordlist);
        return -1;
    }

    result->n = n;
    for (i=0; i<n; i++) {
        ret = parse_float(wordlist[i], result->v + i);
        if (ret < 0) {
            free_wordlist(n, wordlist);
            return ret;
        }
    }

    free_wordlist(n, wordlist);
    return 0;
}

int parse_multi_double(char *arg, var_multi_double_t *result)
{
    int ret;
    int i, n;
    char **wordlist;

    n = parse_wordlist(arg, ",", &wordlist);
    if (n <= 0)
        return -1;

    if (n >= MULTI_VALUE_MAX) {
        printf("you input %d values, should be less than %d\n", n, MULTI_VALUE_MAX);
        free_wordlist(n, wordlist);
        return -1;
    }

    result->n = n;
    for (i=0; i<n; i++) {
        ret = parse_double(wordlist[i], result->v + i);
        if (ret < 0) {
            free_wordlist(n, wordlist);
            return ret;
        }
    }

    free_wordlist(n, wordlist);
    return 0;
}

int parse_multi_range(char *arg, var_multi_range_t *result)
{
    int ret;
    int i, n;
    char **wordlist;

    n = parse_wordlist(arg, ",", &wordlist);
    if (n <= 0)
        return -1;

    if (n >= MULTI_VALUE_MAX) {
        printf("you input %d values, should be less than %d\n", n, MULTI_VALUE_MAX);
        free_wordlist(n, wordlist);
        return -1;
    }

    result->n = n;
    for (i=0; i<n; i++) {
        ret = parse_range(wordlist[i], result->v + i);
        if (ret < 0) {
            free_wordlist(n, wordlist);
            return ret;
        }
    }

    free_wordlist(n, wordlist);
    return 0;
}

/*
 * parse_dirname("")="."
 * parse_dirname("/")="/"
 * parse_dirname("///")="/"
 * parse_dirname("/name1")="/"
 * parse_dirname("///name1")="/"
 * parse_dirname("/name1/name2")="/name1"
 * parse_dirname("/name1/name2/")="/name1"
 * parse_dirname("/name1/name2///")="/name1"
 * parse_dirname("/name1///name2///")="/name1"
 * parse_dirname("////name1////name2///")="////name1"
 * parse_dirname("name1")="."
 * parse_dirname("name1//")="."
 * parse_dirname("name1/name2")="name1"
 * parse_dirname("name1/name2/")="name1"
 * parse_dirname("name1/name2//")="name1"
 */
int parse_dirname(char *path, char **pdir)
{
    char *endp;

    /* empty or NULL string gets treated as "." */
    if (path == NULL || *path == '\0') {
        *pdir = strdup(".");
        return 0;
    }

    /* strip trailing slashes */
    endp = path + strlen(path) - 1;
    while (endp > path && *endp == '/')
        endp--;

    /* find the start of the dir */
    while (endp > path && *endp != '/')
        endp--;

    /* either the dir is "/" or there are no slashes */
    if (endp == path) {
        if (*endp == '/') {
            *pdir = strdup("/");
            return 0;
        } else {
            *pdir = strdup(".");
            return 0;
        }
    }

    do {
        endp--;
    } while (endp > path && *endp == '/');

    *pdir = strndup(path, endp - path + 1);
    return 0;
}

/*
 * parse_basename("")="."
 * parse_basename("/")="/"
 * parse_basename("///")="/"
 * parse_basename("/name1")="name1"
 * parse_basename("///name1")="name1"
 * parse_basename("/name1/name2")="name2"
 * parse_basename("/name1/name2/")="name2"
 * parse_basename("/name1/name2///")="name2"
 * parse_basename("/name1///name2///")="name2"
 * parse_basename("////name1////name2///")="name2"
 * parse_basename("name1")="name1"
 * parse_basename("name1//")="name1"
 * parse_basename("name1/name2")="name2"
 * parse_basename("name1/name2/")="name2"
 * parse_basename("name1/name2//")="name2"
 */
int parse_basename(char *path, char **pbase)
{
    char *endp, *startp;

    /* empty or NULL string gets treated as "." */
    if (path == NULL || *path == '\0') {
        *pbase = strdup(".");
        return 0;
    }

    /* strip trailing slashes */
    endp = path + strlen(path) - 1;
    while (endp > path && *endp == '/')
        endp--;

    /* all slashes becomes "/" */
    if (endp == path && *endp == '/') {
        *pbase = strdup("/");
        return 0;
    }

    /* find the start of the base */
    startp = endp;
    while (startp > path && *(startp - 1) != '/')
        startp--;

    *pbase = strndup(startp, endp - startp + 1);
    return 0;
}

int parse_dirbasename(char *path, char **pdir, char **pbase)
{
    char *endp, *startp;

    /* empty or NULL string gets treated as "." */
    if (path == NULL || *path == '\0') {
        *pdir = strdup(".");
        *pbase = strdup(".");
        return 0;
    }

    /* strip trailing slashes */
    endp = path + strlen(path) - 1;
    while (endp > path && *endp == '/')
        endp--;

    /* all slashes becomes "/" */
    if (endp == path && *endp == '/') {
        *pbase = strdup("/");
    } else {
        /* find the start of the base */
        startp = endp;
        while (startp > path && *(startp - 1) != '/')
            startp--;

        *pbase = strndup(startp, endp - startp + 1);
    }

    /* find the start of the dir */
    while (endp > path && *endp != '/')
        endp--;

    /* either the dir is "/" or there are no slashes */
    if (endp == path) {
        if (*endp == '/') {
            *pdir = strdup("/");
        } else {
            *pdir = strdup(".");
        }

        return 0;
    }

    do {
        endp--;
    } while (endp > path && *endp == '/');

    *pdir = strndup(path, endp - path + 1);

    return 0;
}

int parse_realname(char *path, char **pdir, char **preal, char **pext)
{
    char *dot;
    char *base;

    parse_dirbasename(path, pdir, &base);

    dot = strrchr(base, '.');
    if (dot) {
        *preal = strndup(base, dot - base);
        *pext = strdup(dot + 1);
    } else {
        *preal = strdup(base);
        *pext = strdup("");
    }

    free(base);
    return 0;
}

int parse_url(char *url, char **proto, char **domain)
{
    char *p, *q, *w;

    *proto = NULL;
    *domain = NULL;

    p = url;
    while (*p && *p == ' ') p++;
    if (*p == '\0') return -1;

    q = strstr(p, "://");
    if (q == NULL) {
        fprintf(stderr, "Invalid url %s\n", url);
        return -1;
    }

    *proto = strndup(p, q - p);

    w = strstr(q + 3, "/");
    if (w == NULL) {
        *domain = strdup(q + 3);
        return 0;
    }

    *domain = strndup(q + 3, w - q - 3);

    return 0;
}

int parse_enc_mode(char *arg, int *result)
{
    int ret = -1;

    if (!arg || !result) {
        goto out;
    }


    if (strcasecmp(arg, "ECB") == 0) {
        *result = 0;
    } else if (strcasecmp(arg, "CBC") == 0) {
        *result = 1;
    }else {
        goto out;
    }

    ret = 0;
out:
    return ret;
}

void memdump(unsigned char *buf, int len, int bpr)
{
    int i;
    int rowid = 0;

    for (i = 0; i < len; i++) {
        if (bpr > 0 && (i % bpr == 0)) {
            printf("%04X: ", rowid);
        }

        printf("%02X", buf[i]);
        if (bpr >= 0) {
            if (i % 8 == 7) {
                printf(" ");
            }
        }

        if (bpr > 0) {
            if (i % bpr == (bpr - 1)) {
                printf("\n");
                rowid++;
            } else if (i > 0 && i == len - 1) {
                printf("\n");
            }
        }
    }

    if (bpr > 0) {
        printf("\n");
    }
}

int memparse(char *arg, unsigned char **buf)
{
    int i = 0;
    int len = 0;
    char lv, hv;
    unsigned char *p = NULL;

    len = strlen(arg);
    if (len % 2) {
        return -1;
    }

    p = malloc(len / 2);
    if (p == NULL) {
        return -1;
    }

    *buf = p;
    while (i < len) {
        hv = hexcharcode(arg[i]);
        lv = hexcharcode(arg[i + 1]);
        if (hv == 0x10 || lv == 0x10) {
            free(*buf);

            // we should set the pointer to NULL to avoid the double free issue
            // if we call free(buf) outside.
            *buf = NULL;
            return -1;
        }

        *p = (hv << 4) | lv;
        p += 1;
        i += 2;
    }

    return len / 2;
}

int strnrep(char *dst, char *fmt, char *msg, int n)
{
    int m;
    int idx;
    int argc;
    char **argv = NULL;
    char *d, *p, *q;

    argc = parse_wordlist(msg, "#", &argv);
    if (argc <= 0) {
        strncpy(dst, fmt, n);
        return 0;
    }

    d = dst;
    p = fmt;
    while (*p && n > 1) {
        if (*p == '$') {
            idx = strtol(p + 1, &q, 10);
            if (q == p + 1) {
                *d = *p;
                p++;d++;n--;
            } else {
                if (idx < argc) {
                    m = snprintf(d, (size_t)n, "%s", argv[idx]);
                    d += m;
                    n -= m;
                    p = q;
                } else {
                    *d = *p;
                    p++;d++;n--;
                }
            }
        } else {
            *d = *p;
            p++;d++;n--;
        }
    }

    *d = '\0';
    free_wordlist(argc, argv);
    return 0;
}

