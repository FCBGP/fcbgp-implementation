/**
 * @file strutils.h
 * @author basilguo@163.com
 * @brief 
 * @version 0.0.1
 * @date 2024-07-25
 *
 * @copyright Copyright (c) 2021 - 2024
 */
#ifndef STRUTILS_H
#define STRUTILS_H

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

    extern char *fc_combine_path(const char *const path, const char *const filename);
    extern void fc_utils_str_toupper(char *str, const int size);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif // STRUTILS_H