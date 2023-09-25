#ifndef _LIBXTABLE_H_
#define _LIBXTABLE_H_

#include "libmbs.h"
#include "libdpa.h"
#include "libhtable.h"
#include "libmsgpack.h"

/*
 * libxtable is used to parse a JSON/MSGPACK stream into a hash table
 * with a pair of key and value.
 */

typedef enum {
    XTBL_unk,

    XTBL_u8,
    XTBL_u16,
    XTBL_u32,
    XTBL_u64,
    XTBL_s8,
    XTBL_s16,
    XTBL_s32,
    XTBL_s64,
    XTBL_flt,
    XTBL_dbl,
    XTBL_str,
    XTBL_bin,
    XTBL_map,
    XTBL_arr,
} xtbl_type_t;

#define XTBL_MAX_INT 0xFFFFFFFFFFFFFFFFULL

#define XTBL_INVALID_INT(x) (x == XTBL_MAX_INT)

typedef uint64_t xtbl_int_t;

typedef uint8_t xtbl_u8_t;
typedef uint16_t xtbl_u16_t;
typedef uint32_t xtbl_u32_t;
typedef uint64_t xtbl_u64_t;
typedef int8_t xtbl_s8_t;
typedef int16_t xtbl_s16_t;
typedef int32_t xtbl_s32_t;
typedef int64_t xtbl_s64_t;
typedef float xtbl_flt_t;
typedef double xtbl_dbl_t;
typedef mbs_t xtbl_str_t;
typedef mbs_t xtbl_bin_t;
typedef dpa_t *xtbl_map_t;
typedef dpa_t *xtbl_arr_t;

typedef union xtbl_val_st {
    xtbl_u8_t _u8;
    xtbl_s8_t _s8;
    xtbl_u16_t _u16;
    xtbl_s16_t _s16;
    xtbl_u32_t _u32;
    xtbl_s32_t _s32;
    xtbl_u64_t _u64;
    xtbl_s64_t _s64;
    xtbl_flt_t _flt;
    xtbl_dbl_t _dbl;
    xtbl_str_t _str;
    xtbl_bin_t _bin;
    xtbl_map_t _map;
    xtbl_arr_t _arr;
} xtbl_val_t;

typedef struct xtbl_obj_st {
    htbl_node_t hnode;
    xtbl_type_t type;
    xtbl_str_t path;
    xtbl_str_t key;
    xtbl_val_t *val;
} xtbl_obj_t;

typedef struct xtbl_ctx_st {
    htbl_ctx_t *_tbl;
    xtbl_obj_t *_root;
} xtbl_ctx_t;

extern xtbl_ctx_t *xtbl_create(void);
extern void xtbl_destroy(xtbl_ctx_t *xtbl);
extern xtbl_obj_t *xtbl_find(xtbl_ctx_t *xtbl, char *path);
extern xtbl_ctx_t *xtbl_load_mpack(mpack_ctx_t * mpack);

extern xtbl_int_t xtbl_obj_get_int(xtbl_obj_t *obj);

extern xtbl_u8_t xtbl_obj_get_u8(xtbl_obj_t *obj);
extern xtbl_u16_t xtbl_obj_get_u16(xtbl_obj_t *obj);
extern xtbl_u32_t xtbl_obj_get_u32(xtbl_obj_t *obj);
extern xtbl_u64_t xtbl_obj_get_u64(xtbl_obj_t *obj);
extern xtbl_s8_t xtbl_obj_get_s8(xtbl_obj_t *obj);
extern xtbl_s16_t xtbl_obj_get_s16(xtbl_obj_t *obj);
extern xtbl_s32_t xtbl_obj_get_s32(xtbl_obj_t *obj);
extern xtbl_s64_t xtbl_obj_get_s64(xtbl_obj_t *obj);
extern xtbl_flt_t xtbl_obj_get_flt(xtbl_obj_t *obj);
extern xtbl_dbl_t xtbl_obj_get_dbl(xtbl_obj_t *obj);
extern xtbl_str_t xtbl_obj_get_str(xtbl_obj_t *obj);
extern xtbl_bin_t xtbl_obj_get_bin(xtbl_obj_t *obj);
extern xtbl_map_t xtbl_obj_get_map(xtbl_obj_t *obj);
extern xtbl_arr_t xtbl_obj_get_arr(xtbl_obj_t *obj);

extern xtbl_int_t xtbl_get_int(xtbl_ctx_t *xtbl, char *path);

extern xtbl_u8_t xtbl_get_u8(xtbl_ctx_t *xtbl, char *path);
extern xtbl_u16_t xtbl_get_u16(xtbl_ctx_t *xtbl, char *path);
extern xtbl_u32_t xtbl_get_u32(xtbl_ctx_t *xtbl, char *path);
extern xtbl_u64_t xtbl_get_u64(xtbl_ctx_t *xtbl, char *path);
extern xtbl_s8_t xtbl_get_s8(xtbl_ctx_t *xtbl, char *path);
extern xtbl_s16_t xtbl_get_s16(xtbl_ctx_t *xtbl, char *path);
extern xtbl_s32_t xtbl_get_s32(xtbl_ctx_t *xtbl, char *path);
extern xtbl_s64_t xtbl_get_s64(xtbl_ctx_t *xtbl, char *path);
extern xtbl_flt_t xtbl_get_flt(xtbl_ctx_t *xtbl, char *path);
extern xtbl_dbl_t xtbl_get_dbl(xtbl_ctx_t *xtbl, char *path);
extern xtbl_str_t xtbl_get_str(xtbl_ctx_t *xtbl, char *path);
extern xtbl_bin_t xtbl_get_bin(xtbl_ctx_t *xtbl, char *path);
extern xtbl_map_t xtbl_get_map(xtbl_ctx_t *xtbl, char *path);
extern xtbl_arr_t xtbl_get_arr(xtbl_ctx_t *xtbl, char *path);

#endif
