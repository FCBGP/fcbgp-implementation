#include "libxtable.h"
#include "libstring.h"

static xtbl_val_t *xtbl_val_create(void)
{
    xtbl_val_t *val = malloc(sizeof(xtbl_val_t));
    if (val == NULL) {
        return NULL;
    }

    memset(val, 0, sizeof(xtbl_val_t));
    return val;
}

static void xtbl_val_destroy(xtbl_val_t * val, xtbl_type_t type)
{
    if (val) {
        switch (type) {
        case XTBL_str:
            mbsfree(val->_str);
            break;
        case XTBL_bin:
            mbsfree(val->_bin);
            break;
        case XTBL_map:
            dpa_destroy(val->_map);
            break;
        case XTBL_arr:
            dpa_destroy(val->_arr);
            break;
        default:
            break;
        }
        free(val);
    }
}

static void *xtbl_obj_create(void)
{
    xtbl_obj_t *obj = malloc(sizeof(xtbl_obj_t));
    if (obj == NULL) {
        return NULL;
    }

    memset(obj, 0, sizeof(xtbl_obj_t));
    return obj;
}

static int xtbl_obj_destroy(void *node)
{
    xtbl_obj_t *obj = (xtbl_obj_t *) node;
    if (obj) {
        xtbl_val_destroy(obj->val, obj->type);
        mbsfree(obj->path);
        mbsfree(obj->key);
        free(obj);
    }
    return 0;
}

static int xtbl_obj_display(void *node)
{
    xtbl_obj_t *obj = (xtbl_obj_t *) node;

    printf("%04d obj %p type %d path '%s' key '%s' val ", obj->hnode.idx, obj, obj->type, obj->path, obj->key);
    switch (obj->type) {
    case XTBL_u8: printf("u8 %d\n", obj->val->_u8); break;
    case XTBL_u16: printf("u16 %d\n", obj->val->_u16); break;
    case XTBL_u32: printf("u32 %d\n", obj->val->_u32); break;
    case XTBL_u64: printf("u64 %ld\n", obj->val->_u64); break;
    case XTBL_s8: printf("s8 %d\n", obj->val->_s8); break;
    case XTBL_s16: printf("s16 %d\n", obj->val->_s16); break;
    case XTBL_s32: printf("s32 %d\n", obj->val->_s32); break;
    case XTBL_s64: printf("s64 %ld\n", obj->val->_s64); break;
    case XTBL_flt: printf("flt %f\n", obj->val->_flt); break;
    case XTBL_dbl: printf("dbl %f\n", obj->val->_dbl); break;
    case XTBL_str: printf("str '%s'\n", obj->val->_str); break;
    case XTBL_bin: printf("bin '%s'\n", obj->val->_bin); break;
    case XTBL_map: printf("map %d\n", obj->val->_map->used); break;
    case XTBL_arr: printf("arr %d\n", obj->val->_arr->used); break;
    default: break;
    }

    return 0;
}

static int xtbl_obj_hash(void *node)
{
    xtbl_obj_t *obj = (xtbl_obj_t *) node;

    return strbkdrhash(obj->path, 0x19841128);
}

static int xtbl_obj_cmp(void *base, void *meta)
{
    xtbl_obj_t *bobj = (xtbl_obj_t *) base;
    xtbl_obj_t *mobj = (xtbl_obj_t *) meta;

    return mbscmp(bobj->path, mobj->path);
}

static int xtbl_obj_save(void *base, void *meta)
{
    xtbl_obj_t *bobj = (xtbl_obj_t *) base;
    xtbl_obj_t *mobj = (xtbl_obj_t *) meta;

    bobj->type = mobj->type;
    bobj->path = mobj->path;
    mobj->path = NULL;
    bobj->key = mobj->key;
    mobj->key = NULL;
    bobj->val = mobj->val;
    mobj->val = NULL;
    return 0;
}

static htbl_ops_t g_xtbl_ops = {
    .node_create_func = xtbl_obj_create,
    .node_destroy_func = xtbl_obj_destroy,
    .node_display_func = xtbl_obj_display,
    .node_hash_func = xtbl_obj_hash,
    .meta_hash_func = xtbl_obj_hash,
    .meta_cmp_func = xtbl_obj_cmp,
    .meta_save_func = xtbl_obj_save,
};

#define XTBL_OBJ_INSERT_FUNC(T) \
static xtbl_obj_t *xtbl_obj_insert##T(xtbl_ctx_t *xtbl, xtbl_obj_t *parent, char *key, xtbl##T##_t T) \
{\
    if (key == NULL) {\
        return NULL;\
    }\
    xtbl_obj_t *obj = NULL;\
    xtbl_obj_t *meta = xtbl_obj_create();\
    if (meta == NULL) {\
        return NULL;\
    }\
    xtbl_val_t *val = xtbl_val_create();\
    if (val == NULL) {\
        xtbl_obj_destroy(meta);\
        return NULL;\
    }\
    val->T = T;\
    if (parent) {\
        if (parent == xtbl->_root) {\
            meta->path = mbscatfmt(&meta->path, "%s%s", parent->path, key);\
        } else {\
            meta->path = mbscatfmt(&meta->path, "%s/%s", parent->path, key);\
        }\
    } else {\
        meta->path = mbscatfmt(&meta->path, "/%s", key);\
    }\
    meta->type = XTBL##T;\
    meta->key = key;\
    meta->val = val;\
    obj = htbl_meta_insert(xtbl->_tbl, meta, NULL); \
    if (obj == NULL) {\
        xtbl_obj_destroy(meta);\
        return NULL;\
    }\
    if (parent) {\
        if (parent->type == XTBL_arr) {\
            dpa_push(parent->val->_arr, obj);\
        } else if (parent->type == XTBL_map) {\
            dpa_push(parent->val->_map, obj);\
        }\
    }\
    xtbl_obj_destroy(meta);\
    return obj;\
}

XTBL_OBJ_INSERT_FUNC(_u8)
XTBL_OBJ_INSERT_FUNC(_u16)
XTBL_OBJ_INSERT_FUNC(_u32)
XTBL_OBJ_INSERT_FUNC(_u64)
XTBL_OBJ_INSERT_FUNC(_s8)
XTBL_OBJ_INSERT_FUNC(_s16)
XTBL_OBJ_INSERT_FUNC(_s32)
XTBL_OBJ_INSERT_FUNC(_s64)
XTBL_OBJ_INSERT_FUNC(_flt)
XTBL_OBJ_INSERT_FUNC(_dbl)
XTBL_OBJ_INSERT_FUNC(_str)
XTBL_OBJ_INSERT_FUNC(_bin)
XTBL_OBJ_INSERT_FUNC(_map)
XTBL_OBJ_INSERT_FUNC(_arr)

#define XTBL_OBJ_GET_FUNC(T) \
xtbl##T##_t xtbl_obj_get##T(xtbl_obj_t *obj)\
{\
    if (obj && obj->type == XTBL##T) {\
        return obj->val->T;\
    }\
    return 0;\
}

XTBL_OBJ_GET_FUNC(_u8)
XTBL_OBJ_GET_FUNC(_u16)
XTBL_OBJ_GET_FUNC(_u32)
XTBL_OBJ_GET_FUNC(_u64)
XTBL_OBJ_GET_FUNC(_s8)
XTBL_OBJ_GET_FUNC(_s16)
XTBL_OBJ_GET_FUNC(_s32)
XTBL_OBJ_GET_FUNC(_s64)
XTBL_OBJ_GET_FUNC(_flt)
XTBL_OBJ_GET_FUNC(_dbl)
XTBL_OBJ_GET_FUNC(_str)
XTBL_OBJ_GET_FUNC(_bin)
XTBL_OBJ_GET_FUNC(_map)
XTBL_OBJ_GET_FUNC(_arr)

xtbl_int_t xtbl_obj_get_int(xtbl_obj_t *obj)
{
    if (obj == NULL) {
        return XTBL_MAX_INT;
    }

    switch (obj->type) {
    case XTBL_u8: return obj->val->_u8;
    case XTBL_u16: return obj->val->_u16;
    case XTBL_u32: return obj->val->_u32;
    case XTBL_u64: return obj->val->_u64;
    case XTBL_s8: return obj->val->_s8;
    case XTBL_s16: return obj->val->_s16;
    case XTBL_s32: return obj->val->_s32;
    case XTBL_s64: return obj->val->_s64;
    default: return XTBL_MAX_INT;
    }
}

#define XTBL_GET_FUNC(T) \
xtbl##T##_t xtbl_get##T(xtbl_ctx_t *xtbl, char *path)\
{\
    xtbl_obj_t *obj = xtbl_find(xtbl, path);\
    if (obj && obj->type == XTBL##T) {\
        return obj->val->T;\
    }\
    return 0;\
}

XTBL_GET_FUNC(_u8)
XTBL_GET_FUNC(_u16)
XTBL_GET_FUNC(_u32)
XTBL_GET_FUNC(_u64)
XTBL_GET_FUNC(_s8)
XTBL_GET_FUNC(_s16)
XTBL_GET_FUNC(_s32)
XTBL_GET_FUNC(_s64)
XTBL_GET_FUNC(_flt)
XTBL_GET_FUNC(_dbl)
XTBL_GET_FUNC(_str)
XTBL_GET_FUNC(_bin)
XTBL_GET_FUNC(_map)
XTBL_GET_FUNC(_arr)

xtbl_int_t xtbl_get_int(xtbl_ctx_t *xtbl, char *path)
{
    xtbl_obj_t *obj = xtbl_find(xtbl, path);
    if (obj == NULL) {
        return XTBL_MAX_INT;
    }

    switch (obj->type) {
    case XTBL_u8: return obj->val->_u8;
    case XTBL_u16: return obj->val->_u16;
    case XTBL_u32: return obj->val->_u32;
    case XTBL_u64: return obj->val->_u64;
    case XTBL_s8: return obj->val->_s8;
    case XTBL_s16: return obj->val->_s16;
    case XTBL_s32: return obj->val->_s32;
    case XTBL_s64: return obj->val->_s64;
    default: return XTBL_MAX_INT;
    }
}

xtbl_ctx_t *xtbl_create(void)
{
    xtbl_ctx_t *xtbl = malloc(sizeof(xtbl_ctx_t));
    if (xtbl == NULL) {
        return NULL;
    }

    xtbl->_tbl = htbl_create(1024, &g_xtbl_ops);
    if (xtbl->_tbl == NULL) {
        free(xtbl);
        return NULL;
    }

    xtbl->_root = NULL;
    return xtbl;
}

void xtbl_destroy(xtbl_ctx_t * xtbl)
{
    if (xtbl) {
        htbl_destroy(xtbl->_tbl);
        free(xtbl);
    }
}

xtbl_obj_t *xtbl_find(xtbl_ctx_t * xtbl, char *path)
{
    xtbl_obj_t meta;
    xtbl_obj_t *obj = NULL;

    meta.path = mbsnew(path);
    obj = htbl_meta_find(xtbl->_tbl, &meta);
    if (obj) {
        htbl_node_drop(xtbl->_tbl, obj);
    }

    mbsfree(meta.path);
    return obj;
}

static int xtbl_obj_load_from_mpack(xtbl_ctx_t * xtbl, mpack_ctx_t * mpack, xtbl_obj_t * parent, xtbl_str_t key)
{
    int i = 0;
    xtbl_str_t str = NULL;
    xtbl_map_t map = NULL;
    xtbl_arr_t arr = NULL;
    xtbl_obj_t *obj = NULL;

    mpack_object_t node;
    if (!mpack_read_object(mpack, &node)) {
        return -EBADMSG;
    }

    switch (node.type) {
    case MPACK_TYPE_FIXSTR:
    case MPACK_TYPE_STR8:
    case MPACK_TYPE_STR16:
    case MPACK_TYPE_STR32:
        str = mbsnewsize(node.as.str_size + 1);
        if (str == NULL) {
            return -ENOMEM;
        }

        if (!mpack->read(mpack, str, node.as.str_size)) {
            return -EBADMSG;
        }

        mbssetlen(str, node.as.str_size);
        str[node.as.str_size] = '\0';

        if (key == NULL) {
            return xtbl_obj_load_from_mpack(xtbl, mpack, parent, str);
        }

        obj = xtbl_obj_insert_str(xtbl, parent, key, str);
        if (obj == NULL) {
            mbsfree(key);
            mbsfree(str);
            return -ENOMEM;
        }
        break;

    case MPACK_TYPE_BIN8:
    case MPACK_TYPE_BIN16:
    case MPACK_TYPE_BIN32:
        str = mbsnewsize(node.as.bin_size + 1);
        if (str == NULL) {
            return -ENOMEM;
        }

        if (!mpack->read(mpack, str, node.as.bin_size)) {
            return -EBADMSG;
        }

        mbssetlen(str, node.as.bin_size);
        str[node.as.bin_size] = '\0';

        obj = xtbl_obj_insert_bin(xtbl, parent, key, str);
        if (obj == NULL) {
            mbsfree(key);
            mbsfree(str);
            return -ENOMEM;
        }
        break;

    case MPACK_TYPE_POSITIVE_FIXNUM:
    case MPACK_TYPE_UINT8:
        obj = xtbl_obj_insert_u8(xtbl, parent, key, node.as.u8);
        if (obj == NULL) {
            mbsfree(key);
            return -ENOMEM;
        }
        break;
    case MPACK_TYPE_UINT16:
        obj = xtbl_obj_insert_u16(xtbl, parent, key, node.as.u16);
        if (obj == NULL) {
            mbsfree(key);
            return -ENOMEM;
        }
        break;
    case MPACK_TYPE_UINT32:
        obj = xtbl_obj_insert_u32(xtbl, parent, key, node.as.u32);
        if (obj == NULL) {
            mbsfree(key);
            return -ENOMEM;
        }
        break;
    case MPACK_TYPE_UINT64:
        obj = xtbl_obj_insert_u64(xtbl, parent, key, node.as.u64);
        if (obj == NULL) {
            mbsfree(key);
            return -ENOMEM;
        }
        break;
    case MPACK_TYPE_NEGATIVE_FIXNUM:
    case MPACK_TYPE_SINT8:
        obj = xtbl_obj_insert_s8(xtbl, parent, key, node.as.s8);
        if (obj == NULL) {
            mbsfree(key);
            return -ENOMEM;
        }
        break;
    case MPACK_TYPE_SINT16:
        obj = xtbl_obj_insert_s16(xtbl, parent, key, node.as.s16);
        if (obj == NULL) {
            mbsfree(key);
            return -ENOMEM;
        }
        break;
    case MPACK_TYPE_SINT32:
        obj = xtbl_obj_insert_s32(xtbl, parent, key, node.as.s32);
        if (obj == NULL) {
            mbsfree(key);
            return -ENOMEM;
        }
        break;
    case MPACK_TYPE_SINT64:
        obj = xtbl_obj_insert_s64(xtbl, parent, key, node.as.s64);
        if (obj == NULL) {
            mbsfree(key);
            return -ENOMEM;
        }
        break;
    case MPACK_TYPE_FLOAT:
        obj = xtbl_obj_insert_flt(xtbl, parent, key, node.as.flt);
        if (obj == NULL) {
            mbsfree(key);
            return -ENOMEM;
        }
        break;
    case MPACK_TYPE_DOUBLE:
        obj = xtbl_obj_insert_dbl(xtbl, parent, key, node.as.dbl);
        if (obj == NULL) {
            mbsfree(key);
            return -ENOMEM;
        }
        break;

    case MPACK_TYPE_FIXMAP:
    case MPACK_TYPE_MAP16:
    case MPACK_TYPE_MAP32:
        map = dpa_create(node.as.map_size);
        if (map == NULL) {
            return -ENOMEM;
        }

        if (parent == NULL && key == NULL) {
            key = mbsempty();
        }

        obj = xtbl_obj_insert_map(xtbl, parent, key, map);
        if (obj == NULL) {
            dpa_destroy(map);
            return -ENOMEM;
        }

        if (xtbl->_root == NULL) {
            xtbl->_root = obj;
        }

        for (i = 0; i < node.as.map_size; i++) {
            xtbl_obj_load_from_mpack(xtbl, mpack, obj, NULL);
        }
        break;
    case MPACK_TYPE_FIXARRAY:
    case MPACK_TYPE_ARRAY16:
    case MPACK_TYPE_ARRAY32:
        arr = dpa_create(node.as.array_size);
        if (arr == NULL) {
            return -ENOMEM;
        }

        obj = xtbl_obj_insert_arr(xtbl, parent, key, arr);
        if (obj == NULL) {
            dpa_destroy(arr);
            return -ENOMEM;
        }

        for (i = 0; i < node.as.array_size; i++) {
            xtbl_str_t idx = NULL;
            idx = mbscatfmt(&idx, "[%d]", i);
            xtbl_obj_load_from_mpack(xtbl, mpack, obj, idx);
        }
        break;
    case MPACK_TYPE_NIL:
    case MPACK_TYPE_BOOLEAN:
    case MPACK_TYPE_EXT8:
    case MPACK_TYPE_EXT16:
    case MPACK_TYPE_EXT32:
    case MPACK_TYPE_FIXEXT1:
    case MPACK_TYPE_FIXEXT2:
    case MPACK_TYPE_FIXEXT4:
    case MPACK_TYPE_FIXEXT8:
    case MPACK_TYPE_FIXEXT16:
    default:
        fprintf(stderr, "Unrecognized object type %u\n", node.type);
        return -EINVAL;
    }

    return 0;
}

xtbl_ctx_t *xtbl_load_mpack(mpack_ctx_t *mpack)
{
    int ret = -1;
    xtbl_ctx_t *xtbl = xtbl_create();
    if (xtbl == NULL) {
        return NULL;
    }

    ret = xtbl_obj_load_from_mpack(xtbl, mpack, xtbl->_root, NULL);
    if (ret < 0) {
        xtbl_destroy(xtbl);
        return NULL;
    }

    return xtbl;
}

