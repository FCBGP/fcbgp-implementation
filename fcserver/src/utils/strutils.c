/**
 * @file utils.c
 * @author basilguo@163.com
 * @brief
 * @version 0.0.1
 * @date 2024-07-25
 *
 * @copyright Copyright (c) 2021 - 2024
 */

#ifdef __cplusplus
extern "C"
{
#endif /* __cplusplus */

#include "strutils.h"
#include "colorp.h"
#include "libdiag.h"
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
    /**
     * If the user forgets to remove the tail '/', we need to properly accept that.
     * @param path      path
     * @param filename  filename
     * @return          Return the combined fullpath
     * */
    char *fc_combine_path(const char *const path, const char *const filename)
    {
        size_t path_len = strlen(path);
        size_t filename_len = strlen(filename);
        size_t combined_len = path_len + filename_len + 2; // 2 for '/' and '\0'

        char *combined_path = (char *)malloc(combined_len);
        if (combined_path == NULL)
        {
            DIAG_ERROR("malloc for combined_path failed\n");
            return NULL;
        }
        memset(combined_path, 0, combined_len);

        memcpy(combined_path, path, strlen(path));
        if (path_len > 0 && path[path_len - 1] != '/')
        {
            strcat(combined_path, "/");
        }

        strcat(combined_path, filename);

        return combined_path;
    }

    /**
     * To uppercase of string, in place.
     * @param str   input string
     * @param size  input string size
     * @return      none.
     * */
    void fc_utils_str_toupper(char *str, const int size)
    {
        int i = 0;
        if (str)
        {
            for (i = 0; i < size; ++i)
            {
                str[i] = toupper(str[i]);
            }

            str[size] = '\0';
        }
    }

    int fc_print_bin(const char *msg, const unsigned char *bin, const int binlen)
    {
        int curlen = 0;
        int binstrlen = 2 * binlen + 1;
        char *binstr = calloc(binstrlen, sizeof(unsigned char));
        for (int i = 0; i < binlen; i++)
        {
            snprintf(binstr + curlen, binstrlen, "%02X", bin[i]);
            curlen += 2;
        }
        DIAG_INFO("%s: %s\n", msg, binstr);
        free(binstr);

        return 0;
    }
#ifdef __cplusplus
}
#endif /* __cplusplus */
