/*
  Copyright (c) 2009 Dave Gamble

  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to deal
  in the Software without restriction, including without limitation the rights
  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  copies of the Software, and to permit persons to whom the Software is
  furnished to do so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in
  all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
  THE SOFTWARE.
*/

#ifndef cJSON__h
#define cJSON__h

#ifdef __cplusplus
extern "C"
{
#endif

/* project version */
#define CJSON_VERSION_MAJOR 1
#define CJSON_VERSION_MINOR 3
#define CJSON_VERSION_PATCH 2

    /* returns the version of cJSON as a string */
    extern const char* cJSON_Version(void);

#include <stddef.h>

/* cJSON Types: */
#define cJSON_Invalid (0)
#define cJSON_False (1 << 0)
#define cJSON_True (1 << 1)
#define cJSON_NULL (1 << 2)
#define cJSON_Number (1 << 3)
#define cJSON_String (1 << 4)
#define cJSON_Array (1 << 5)
#define cJSON_Object (1 << 6)
#define cJSON_Raw (1 << 7) /* raw json */

#define cJSON_IsReference 256
#define cJSON_StringIsConst 512

    /* The cJSON structure: */
    typedef struct cJSON
    {
        /* next/prev allow you to walk array/object chains. Alternatively, use
         * GetArraySize/GetArrayItem/GetObjectItem */
        struct cJSON* next;
        struct cJSON* prev;
        /* An array or object item will have a child pointer pointing to a chain
         * of the items in the array/object. */
        struct cJSON* child;

        /* The type of the item, as above. */
        int type;

        /* The item's string, if type==cJSON_String  and type == cJSON_Raw */
        char* valuestring;
        /* The item's number, if type==cJSON_Number */
        int valueint;
        /* The item's number, if type==cJSON_Number */
        double valuedouble;

        /* The item's name string, if this item is the child of, or is in the
         * list of subitems of an object. */
        char* string;
    } cJSON;

    typedef struct cJSON_Hooks
    {
        void* (*malloc_fn)(size_t sz);
        void (*free_fn)(void* ptr);
    } cJSON_Hooks;

    /* Supply malloc, realloc and free functions to cJSON */
    extern void cJSON_InitHooks(cJSON_Hooks* hooks);

    /* Supply a block of JSON, and this returns a cJSON object you can
     * interrogate. Call cJSON_Delete when finished. */
    extern cJSON* cJSON_Parse(const char* value);
    /* Render a cJSON entity to text for transfer/storage. Free the char* when
     * finished. */
    extern char* cJSON_Print(const cJSON* item);
    /* Render a cJSON entity to text for transfer/storage without any
     * formatting. Free the char* when finished. */
    extern char* cJSON_PrintUnformatted(const cJSON* item);
    /* Render a cJSON entity to text using a buffered strategy. prebuffer is a
     * guess at the final size. guessing well reduces reallocation. fmt=0 gives
     * unformatted, =1 gives formatted */
    extern char* cJSON_PrintBuffered(const cJSON* item, int prebuffer, int fmt);
    /* Render a cJSON entity to text using a buffer already allocated in memory
     * with length buf_len. Returns 1 on success and 0 on failure. */
    extern int cJSON_PrintPreallocated(cJSON* item, char* buf, const int len,
                                       const int fmt);
    /* Delete a cJSON entity and all subentities. */
    extern void cJSON_Delete(cJSON* c);

    /* Returns the number of items in an array (or object). */
    extern int cJSON_GetArraySize(const cJSON* array);
    /* Retrieve item number "item" from array "array". Returns NULL if
     * unsuccessful.
     */
    extern cJSON* cJSON_GetArrayItem(const cJSON* array, int item);
    /* Get item "string" from object. Case insensitive. */
    extern cJSON* cJSON_GetObjectItem(const cJSON* object, const char* string);
    extern int cJSON_HasObjectItem(const cJSON* object, const char* string);
    /* For analysing failed parses. This returns a pointer to the parse error.
     * You'll probably need to look a few chars back to make sense of it.
     * Defined when cJSON_Parse() returns 0. 0 when cJSON_Parse() succeeds. */
    extern const char* cJSON_GetErrorPtr(void);

    /* These calls create a cJSON item of the appropriate type. */
    extern cJSON* cJSON_CreateNull(void);
    extern cJSON* cJSON_CreateTrue(void);
    extern cJSON* cJSON_CreateFalse(void);
    extern cJSON* cJSON_CreateBool(int b);
    extern cJSON* cJSON_CreateNumber(double num);
    extern cJSON* cJSON_CreateString(const char* string);
    /* raw json */
    extern cJSON* cJSON_CreateRaw(const char* raw);
    extern cJSON* cJSON_CreateArray(void);
    extern cJSON* cJSON_CreateObject(void);

    /* These utilities create an Array of count items. */
    extern cJSON* cJSON_CreateIntArray(const int* numbers, int count);
    extern cJSON* cJSON_CreateFloatArray(const float* numbers, int count);
    extern cJSON* cJSON_CreateDoubleArray(const double* numbers, int count);
    extern cJSON* cJSON_CreateStringArray(const char** strings, int count);

    /* Append item to the specified array/object. */
    extern void cJSON_AddItemToArray(cJSON* array, cJSON* item);
    extern void cJSON_AddItemToObject(cJSON* object, const char* string,
                                      cJSON* item);
    /* Use this when string is definitely const (i.e. a literal, or as good as),
     * and will definitely survive the cJSON object. WARNING: When this function
     * was used, make sure to always check that (item->type &
     * cJSON_StringIsConst) is zero before writing to `item->string` */
    extern void cJSON_AddItemToObjectCS(cJSON* object, const char* string,
                                        cJSON* item);
    /* Append reference to item to the specified array/object. Use this when you
     * want to add an existing cJSON to a new cJSON, but don't want to corrupt
     * your existing cJSON. */
    extern void cJSON_AddItemReferenceToArray(cJSON* array, cJSON* item);
    extern void cJSON_AddItemReferenceToObject(cJSON* object,
                                               const char* string, cJSON* item);

    /* Remove/Detatch items from Arrays/Objects. */
    extern cJSON* cJSON_DetachItemFromArray(cJSON* array, int which);
    extern void cJSON_DeleteItemFromArray(cJSON* array, int which);
    extern cJSON* cJSON_DetachItemFromObject(cJSON* object, const char* string);
    extern void cJSON_DeleteItemFromObject(cJSON* object, const char* string);

    /* Update array items. */
    extern void cJSON_InsertItemInArray(
        cJSON* array, int which,
        cJSON* newitem); /* Shifts pre-existing items to the right. */
    extern void cJSON_ReplaceItemInArray(cJSON* array, int which,
                                         cJSON* newitem);
    extern void cJSON_ReplaceItemInObject(cJSON* object, const char* string,
                                          cJSON* newitem);

    /* Duplicate a cJSON item */
    extern cJSON* cJSON_Duplicate(const cJSON* item, int recurse);
    /* Duplicate will create a new, identical cJSON item to the one you pass, in
    new memory that will need to be released. With recurse!=0, it will duplicate
    any children connected to the item. The item->next and ->prev pointers are
    always zero on return from Duplicate. */

    /* ParseWithOpts allows you to require (and check) that the JSON is null
     * terminated, and to retrieve the pointer to the final byte parsed. */
    /* If you supply a ptr in return_parse_end and parsing fails, then
     * return_parse_end will contain a pointer to the error. If not, then
     * cJSON_GetErrorPtr() does the job. */
    extern cJSON* cJSON_ParseWithOpts(const char* value,
                                      const char** return_parse_end,
                                      int require_null_terminated);

    extern void cJSON_Minify(char* json);

/* Macros for creating things quickly. */
#define cJSON_AddNullToObject(object, name)                                    \
    cJSON_AddItemToObject(object, name, cJSON_CreateNull())
#define cJSON_AddTrueToObject(object, name)                                    \
    cJSON_AddItemToObject(object, name, cJSON_CreateTrue())
#define cJSON_AddFalseToObject(object, name)                                   \
    cJSON_AddItemToObject(object, name, cJSON_CreateFalse())
#define cJSON_AddBoolToObject(object, name, b)                                 \
    cJSON_AddItemToObject(object, name, cJSON_CreateBool(b))
#define cJSON_AddNumberToObject(object, name, n)                               \
    cJSON_AddItemToObject(object, name, cJSON_CreateNumber(n))
#define cJSON_AddStringToObject(object, name, s)                               \
    cJSON_AddItemToObject(object, name, cJSON_CreateString(s))
#define cJSON_AddRawToObject(object, name, s)                                  \
    cJSON_AddItemToObject(object, name, cJSON_CreateRaw(s))

/* When assigning an integer value, it needs to be propagated to valuedouble
 * too. */
#define cJSON_SetIntValue(object, number)                                      \
    ((object) ? (object)->valueint = (object)->valuedouble = (number)          \
              : (number))
    /* helper for the cJSON_SetNumberValue macro */
    extern double cJSON_SetNumberHelper(cJSON* object, double number);
#define cJSON_SetNumberValue(object, number)                                   \
    ((object) ? cJSON_SetNumberHelper(object, (double)number) : (number))

/* Macro for iterating over an array */
#define cJSON_ArrayForEach(pos, head)                                          \
    for (pos = (head)->child; pos != NULL; pos = pos->next)

#ifdef __cplusplus
}
#endif

#endif
