#ifndef __LIBMSGPACK_H__
#define __LIBMSGPACK_H__

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdarg.h>

struct mpack_ctx_st;

typedef bool(*mpack_reader_t) (struct mpack_ctx_st * ctx, void *data, size_t limit);
typedef size_t(*mpack_writer_t) (struct mpack_ctx_st * ctx, const void *data, size_t count);

enum {
    MPACK_TYPE_POSITIVE_FIXNUM, /*  0 */
    MPACK_TYPE_FIXMAP,          /*  1 */
    MPACK_TYPE_FIXARRAY,        /*  2 */
    MPACK_TYPE_FIXSTR,          /*  3 */
    MPACK_TYPE_NIL,             /*  4 */
    MPACK_TYPE_BOOLEAN,         /*  5 */
    MPACK_TYPE_BIN8,            /*  6 */
    MPACK_TYPE_BIN16,           /*  7 */
    MPACK_TYPE_BIN32,           /*  8 */
    MPACK_TYPE_EXT8,            /*  9 */
    MPACK_TYPE_EXT16,           /* 10 */
    MPACK_TYPE_EXT32,           /* 11 */
    MPACK_TYPE_FLOAT,           /* 12 */
    MPACK_TYPE_DOUBLE,          /* 13 */
    MPACK_TYPE_UINT8,           /* 14 */
    MPACK_TYPE_UINT16,          /* 15 */
    MPACK_TYPE_UINT32,          /* 16 */
    MPACK_TYPE_UINT64,          /* 17 */
    MPACK_TYPE_SINT8,           /* 18 */
    MPACK_TYPE_SINT16,          /* 19 */
    MPACK_TYPE_SINT32,          /* 20 */
    MPACK_TYPE_SINT64,          /* 21 */
    MPACK_TYPE_FIXEXT1,         /* 22 */
    MPACK_TYPE_FIXEXT2,         /* 23 */
    MPACK_TYPE_FIXEXT4,         /* 24 */
    MPACK_TYPE_FIXEXT8,         /* 25 */
    MPACK_TYPE_FIXEXT16,        /* 26 */
    MPACK_TYPE_STR8,            /* 27 */
    MPACK_TYPE_STR16,           /* 28 */
    MPACK_TYPE_STR32,           /* 29 */
    MPACK_TYPE_ARRAY16,         /* 30 */
    MPACK_TYPE_ARRAY32,         /* 31 */
    MPACK_TYPE_MAP16,           /* 32 */
    MPACK_TYPE_MAP32,           /* 33 */
    MPACK_TYPE_NEGATIVE_FIXNUM  /* 34 */
};

typedef struct mpack_ext_st {
    int8_t type;
    uint32_t size;
} mpack_ext_t;

typedef union mpack_object_data_un {
    bool boolean;
    uint8_t u8;
    uint16_t u16;
    uint32_t u32;
    uint64_t u64;
    int8_t s8;
    int16_t s16;
    int32_t s32;
    int64_t s64;
    float flt;
    double dbl;
    uint32_t array_size;
    uint32_t map_size;
    uint32_t str_size;
    uint32_t bin_size;
    mpack_ext_t ext;
} mpack_object_data_t;

typedef struct mpack_ctx_st {
    uint8_t error;
    void *buf;
    mpack_reader_t read;
    mpack_writer_t write;
} mpack_ctx_t;

typedef struct mpack_object_st {
    uint8_t type;
    mpack_object_data_t as;
} mpack_object_t;

/*
 * ============================================================================
 * === Main API
 * ============================================================================
 */

/* Initializes a MsgPack context */
void mpack_init(mpack_ctx_t * ctx, void *buf, mpack_reader_t read, mpack_writer_t write);

/* Returns MsgPack's version */
uint32_t mpack_version(void);

/* Returns the MessagePack version employed by MsgPack */
uint32_t mpack_mp_version(void);

/* Returns a string description of a MsgPack context's error */
const char *mpack_strerror(mpack_ctx_t * ctx);

/* Writes a signed integer to the backend */
bool mpack_write_integer(mpack_ctx_t * ctx, int64_t d);

/* Writes an unsigned integer to the backend */
bool mpack_write_uinteger(mpack_ctx_t * ctx, uint64_t u);

/*
 * Writes a floating-point value (either single or double-precision) to the
 * backend
 */
bool mpack_write_decimal(mpack_ctx_t * ctx, double d);

/* Writes NULL to the backend */
bool mpack_write_nil(mpack_ctx_t * ctx);

/* Writes true to the backend */
bool mpack_write_true(mpack_ctx_t * ctx);

/* Writes false to the backend */
bool mpack_write_false(mpack_ctx_t * ctx);

/* Writes a boolean value to the backend */
bool mpack_write_bool(mpack_ctx_t * ctx, bool b);

/*
 * Writes an unsigned char's value to the backend as a boolean.  This is useful
 * if you are using a different boolean type in your application.
 */
bool mpack_write_u8_as_bool(mpack_ctx_t * ctx, uint8_t b);

/*
 * Writes a string to the backend; according to the MessagePack spec, this must
 * be encoded using UTF-8, but MsgPack leaves that job up to the programmer.
 */
bool mpack_write_str(mpack_ctx_t * ctx, const char *data, uint32_t size);
bool mpack_write_str_for_snmp(mpack_ctx_t * ctx, const char *data, uint32_t size);
bool mpack_write_fmt(mpack_ctx_t * ctx, const char *fmt, ...);

/*
 * Writes a string to the backend.  This avoids using the STR8 marker, which
 * is unsupported by MessagePack v4, the version implemented by many other
 * MessagePack libraries.  No encoding is assumed in this case, not that it
 * matters.
 */
bool mpack_write_str_v4(mpack_ctx_t * ctx, const char *data, uint32_t size);

/*
 * Writes the string marker to the backend.  This is useful if you are writing
 * data in chunks instead of a single shot.
 */
bool mpack_write_str_marker(mpack_ctx_t * ctx, uint32_t size);

/*
 * Writes the string marker to the backend.  This is useful if you are writing
 * data in chunks instead of a single shot.  This avoids using the STR8
 * marker, which is unsupported by MessagePack v4, the version implemented by
 * many other MessagePack libraries.  No encoding is assumed in this case, not
 * that it matters.
 */
bool mpack_write_str_marker_v4(mpack_ctx_t * ctx, uint32_t size);

/* Writes binary data to the backend */
bool mpack_write_bin(mpack_ctx_t * ctx, const void *data, uint32_t size);

/*
 * Writes the binary data marker to the backend.  This is useful if you are
 * writing data in chunks instead of a single shot.
 */
bool mpack_write_bin_marker(mpack_ctx_t * ctx, uint32_t size);

/* Writes an array to the backend. */
bool mpack_write_array(mpack_ctx_t * ctx, uint32_t size);

/* Writes a map to the backend. */
bool mpack_write_map(mpack_ctx_t * ctx, uint32_t size);

/* Writes an extended type to the backend */
bool mpack_write_ext(mpack_ctx_t * ctx, int8_t type, uint32_t size, const void *data);

/*
 * Writes the extended type marker to the backend.  This is useful if you want
 * to write the type's data in chunks instead of a single shot.
 */
bool mpack_write_ext_marker(mpack_ctx_t * ctx, int8_t type, uint32_t size);

/* Writes an object to the backend */
bool mpack_write_object(mpack_ctx_t * ctx, mpack_object_t * obj);

/*
 * Writes an object to the backend. This avoids using the STR8 marker, which
 * is unsupported by MessagePack v4, the version implemented by many other
 * MessagePack libraries.
 */
bool mpack_write_object_v4(mpack_ctx_t * ctx, mpack_object_t * obj);

/* Reads a signed integer that fits inside a signed char */
bool mpack_read_char(mpack_ctx_t * ctx, int8_t * c);

/* Reads a signed integer that fits inside a signed short */
bool mpack_read_short(mpack_ctx_t * ctx, int16_t * s);

/* Reads a signed integer that fits inside a signed int */
bool mpack_read_int(mpack_ctx_t * ctx, int32_t * i);

/* Reads a signed integer that fits inside a signed long */
bool mpack_read_long(mpack_ctx_t * ctx, int64_t * d);

/* Reads a signed integer */
bool mpack_read_integer(mpack_ctx_t * ctx, int64_t * d);

/* Reads an unsigned integer that fits inside an unsigned char */
bool mpack_read_uchar(mpack_ctx_t * ctx, uint8_t * c);

/* Reads an unsigned integer that fits inside an unsigned short */
bool mpack_read_ushort(mpack_ctx_t * ctx, uint16_t * s);

/* Reads an unsigned integer that fits inside an unsigned int */
bool mpack_read_uint(mpack_ctx_t * ctx, uint32_t * i);

/* Reads an unsigned integer that fits inside an unsigned long */
bool mpack_read_ulong(mpack_ctx_t * ctx, uint64_t * u);

/* Reads an unsigned integer */
bool mpack_read_uinteger(mpack_ctx_t * ctx, uint64_t * u);

/*
 * Reads a floating point value (either single or double-precision) from the
 * backend
 */
bool mpack_read_decimal(mpack_ctx_t * ctx, double *d);

/* "Reads" (more like "skips") a NULL value from the backend */
bool mpack_read_nil(mpack_ctx_t * ctx);

/* Reads a boolean from the backend */
bool mpack_read_bool(mpack_ctx_t * ctx, bool * b);

/*
 * Reads a boolean as an unsigned char from the backend; this is useful if your
 * application uses a different boolean type.
 */
bool mpack_read_bool_as_u8(mpack_ctx_t * ctx, uint8_t * b);

/* Reads a string's size from the backend */
bool mpack_read_str_size(mpack_ctx_t * ctx, uint32_t * size);

/*
 * Reads a string from the backend; according to the spec, the string's data
 * ought to be encoded using UTF-8,
 */
bool mpack_read_str(mpack_ctx_t * ctx, char *data, uint32_t * size);

/* Reads the size of packed binary data from the backend */
bool mpack_read_bin_size(mpack_ctx_t * ctx, uint32_t * size);

/* Reads packed binary data from the backend */
bool mpack_read_bin(mpack_ctx_t * ctx, void *data, uint32_t * size);

/* Reads an array from the backend */
bool mpack_read_array(mpack_ctx_t * ctx, uint32_t * size);

/* Reads a map from the backend */
bool mpack_read_map(mpack_ctx_t * ctx, uint32_t * size);

/* Reads the extended type's marker from the backend */
bool mpack_read_ext_marker(mpack_ctx_t * ctx, int8_t * type, uint32_t * size);

/* Reads an extended type from the backend */
bool mpack_read_ext(mpack_ctx_t * ctx, int8_t * type, uint32_t * size, void *data);

/* Reads an object from the backend */
bool mpack_read_object(mpack_ctx_t * ctx, mpack_object_t * obj);

/*
 * ============================================================================
 * === Specific API
 * ============================================================================
 */

bool mpack_write_pfix(mpack_ctx_t * ctx, uint8_t c);
bool mpack_write_nfix(mpack_ctx_t * ctx, int8_t c);

bool mpack_write_sfix(mpack_ctx_t * ctx, int8_t c);
bool mpack_write_s8(mpack_ctx_t * ctx, int8_t c);
bool mpack_write_s16(mpack_ctx_t * ctx, int16_t s);
bool mpack_write_s32(mpack_ctx_t * ctx, int32_t i);
bool mpack_write_s64(mpack_ctx_t * ctx, int64_t l);

bool mpack_write_ufix(mpack_ctx_t * ctx, uint8_t c);
bool mpack_write_u8(mpack_ctx_t * ctx, uint8_t c);
bool mpack_write_u16(mpack_ctx_t * ctx, uint16_t s);
bool mpack_write_u32(mpack_ctx_t * ctx, uint32_t i);
bool mpack_write_u64(mpack_ctx_t * ctx, uint64_t l);

bool mpack_write_float(mpack_ctx_t * ctx, float f);
bool mpack_write_double(mpack_ctx_t * ctx, double d);

bool mpack_write_fixstr_marker(mpack_ctx_t * ctx, uint8_t size);
bool mpack_write_fixstr(mpack_ctx_t * ctx, const char *data, uint8_t size);
bool mpack_write_str8_marker(mpack_ctx_t * ctx, uint8_t size);
bool mpack_write_str8(mpack_ctx_t * ctx, const char *data, uint8_t size);
bool mpack_write_str16_marker(mpack_ctx_t * ctx, uint16_t size);
bool mpack_write_str16(mpack_ctx_t * ctx, const char *data, uint16_t size);
bool mpack_write_str32_marker(mpack_ctx_t * ctx, uint32_t size);
bool mpack_write_str32(mpack_ctx_t * ctx, const char *data, uint32_t size);

bool mpack_write_bin8_marker(mpack_ctx_t * ctx, uint8_t size);
bool mpack_write_bin8(mpack_ctx_t * ctx, const void *data, uint8_t size);
bool mpack_write_bin16_marker(mpack_ctx_t * ctx, uint16_t size);
bool mpack_write_bin16(mpack_ctx_t * ctx, const void *data, uint16_t size);
bool mpack_write_bin32_marker(mpack_ctx_t * ctx, uint32_t size);
bool mpack_write_bin32(mpack_ctx_t * ctx, const void *data, uint32_t size);

bool mpack_write_fixarray(mpack_ctx_t * ctx, uint8_t size);
bool mpack_write_array16(mpack_ctx_t * ctx, uint16_t size);
bool mpack_write_array32(mpack_ctx_t * ctx, uint32_t size);

bool mpack_write_fixmap(mpack_ctx_t * ctx, uint8_t size);
bool mpack_write_map16(mpack_ctx_t * ctx, uint16_t size);
bool mpack_write_map32(mpack_ctx_t * ctx, uint32_t size);

bool mpack_write_fixext1_marker(mpack_ctx_t * ctx, int8_t type);
bool mpack_write_fixext1(mpack_ctx_t * ctx, int8_t type, const void *data);
bool mpack_write_fixext2_marker(mpack_ctx_t * ctx, int8_t type);
bool mpack_write_fixext2(mpack_ctx_t * ctx, int8_t type, const void *data);
bool mpack_write_fixext4_marker(mpack_ctx_t * ctx, int8_t type);
bool mpack_write_fixext4(mpack_ctx_t * ctx, int8_t type, const void *data);
bool mpack_write_fixext8_marker(mpack_ctx_t * ctx, int8_t type);
bool mpack_write_fixext8(mpack_ctx_t * ctx, int8_t type, const void *data);
bool mpack_write_fixext16_marker(mpack_ctx_t * ctx, int8_t type);
bool mpack_write_fixext16(mpack_ctx_t * ctx, int8_t type, const void *data);

bool mpack_write_ext8_marker(mpack_ctx_t * ctx, int8_t type, uint8_t size);
bool mpack_write_ext8(mpack_ctx_t * ctx, int8_t type, uint8_t size, const void *data);
bool mpack_write_ext16_marker(mpack_ctx_t * ctx, int8_t type, uint16_t size);
bool mpack_write_ext16(mpack_ctx_t * ctx, int8_t type, uint16_t size, const void *data);
bool mpack_write_ext32_marker(mpack_ctx_t * ctx, int8_t type, uint32_t size);
bool mpack_write_ext32(mpack_ctx_t * ctx, int8_t type, uint32_t size, const void *data);

bool mpack_read_pfix(mpack_ctx_t * ctx, uint8_t * c);
bool mpack_read_nfix(mpack_ctx_t * ctx, int8_t * c);

bool mpack_read_sfix(mpack_ctx_t * ctx, int8_t * c);
bool mpack_read_s8(mpack_ctx_t * ctx, int8_t * c);
bool mpack_read_s16(mpack_ctx_t * ctx, int16_t * s);
bool mpack_read_s32(mpack_ctx_t * ctx, int32_t * i);
bool mpack_read_s64(mpack_ctx_t * ctx, int64_t * l);

bool mpack_read_ufix(mpack_ctx_t * ctx, uint8_t * c);
bool mpack_read_u8(mpack_ctx_t * ctx, uint8_t * c);
bool mpack_read_u16(mpack_ctx_t * ctx, uint16_t * s);
bool mpack_read_u32(mpack_ctx_t * ctx, uint32_t * i);
bool mpack_read_u64(mpack_ctx_t * ctx, uint64_t * l);

bool mpack_read_float(mpack_ctx_t * ctx, float *f);
bool mpack_read_double(mpack_ctx_t * ctx, double *d);

bool mpack_read_fixext1_marker(mpack_ctx_t * ctx, int8_t * type);
bool mpack_read_fixext1(mpack_ctx_t * ctx, int8_t * type, void *data);
bool mpack_read_fixext2_marker(mpack_ctx_t * ctx, int8_t * type);
bool mpack_read_fixext2(mpack_ctx_t * ctx, int8_t * type, void *data);
bool mpack_read_fixext4_marker(mpack_ctx_t * ctx, int8_t * type);
bool mpack_read_fixext4(mpack_ctx_t * ctx, int8_t * type, void *data);
bool mpack_read_fixext8_marker(mpack_ctx_t * ctx, int8_t * type);
bool mpack_read_fixext8(mpack_ctx_t * ctx, int8_t * type, void *data);
bool mpack_read_fixext16_marker(mpack_ctx_t * ctx, int8_t * type);
bool mpack_read_fixext16(mpack_ctx_t * ctx, int8_t * type, void *data);

bool mpack_read_ext8_marker(mpack_ctx_t * ctx, int8_t * type, uint8_t * size);
bool mpack_read_ext8(mpack_ctx_t * ctx, int8_t * type, uint8_t * size, void *data);
bool mpack_read_ext16_marker(mpack_ctx_t * ctx, int8_t * type, uint16_t * size);
bool mpack_read_ext16(mpack_ctx_t * ctx, int8_t * type, uint16_t * size, void *data);
bool mpack_read_ext32_marker(mpack_ctx_t * ctx, int8_t * type, uint32_t * size);
bool mpack_read_ext32(mpack_ctx_t * ctx, int8_t * type, uint32_t * size, void *data);

/*
 * ============================================================================
 * === Object API
 * ============================================================================
 */

bool mpack_object_is_char(mpack_object_t * obj);
bool mpack_object_is_short(mpack_object_t * obj);
bool mpack_object_is_int(mpack_object_t * obj);
bool mpack_object_is_long(mpack_object_t * obj);
bool mpack_object_is_sinteger(mpack_object_t * obj);
bool mpack_object_is_uchar(mpack_object_t * obj);
bool mpack_object_is_ushort(mpack_object_t * obj);
bool mpack_object_is_uint(mpack_object_t * obj);
bool mpack_object_is_ulong(mpack_object_t * obj);
bool mpack_object_is_uinteger(mpack_object_t * obj);
bool mpack_object_is_float(mpack_object_t * obj);
bool mpack_object_is_double(mpack_object_t * obj);
bool mpack_object_is_nil(mpack_object_t * obj);
bool mpack_object_is_bool(mpack_object_t * obj);
bool mpack_object_is_str(mpack_object_t * obj);
bool mpack_object_is_bin(mpack_object_t * obj);
bool mpack_object_is_array(mpack_object_t * obj);
bool mpack_object_is_map(mpack_object_t * obj);
bool mpack_object_is_ext(mpack_object_t * obj);

bool mpack_object_as_char(mpack_object_t * obj, int8_t * c);
bool mpack_object_as_short(mpack_object_t * obj, int16_t * s);
bool mpack_object_as_int(mpack_object_t * obj, int32_t * i);
bool mpack_object_as_long(mpack_object_t * obj, int64_t * d);
bool mpack_object_as_sinteger(mpack_object_t * obj, int64_t * d);
bool mpack_object_as_uchar(mpack_object_t * obj, uint8_t * c);
bool mpack_object_as_ushort(mpack_object_t * obj, uint16_t * s);
bool mpack_object_as_uint(mpack_object_t * obj, uint32_t * i);
bool mpack_object_as_ulong(mpack_object_t * obj, uint64_t * u);
bool mpack_object_as_uinteger(mpack_object_t * obj, uint64_t * u);
bool mpack_object_as_float(mpack_object_t * obj, float *f);
bool mpack_object_as_double(mpack_object_t * obj, double *d);
bool mpack_object_as_bool(mpack_object_t * obj, bool * b);
bool mpack_object_as_str(mpack_object_t * obj, uint32_t * size);
bool mpack_object_as_bin(mpack_object_t * obj, uint32_t * size);
bool mpack_object_as_array(mpack_object_t * obj, uint32_t * size);
bool mpack_object_as_map(mpack_object_t * obj, uint32_t * size);
bool mpack_object_as_ext(mpack_object_t * obj, int8_t * type, uint32_t * size);

bool mpack_object_to_str(mpack_ctx_t * ctx, mpack_object_t * obj, char *data, uint32_t buf_size);
bool mpack_object_to_bin(mpack_ctx_t * ctx, mpack_object_t * obj, void *data, uint32_t buf_size);

/*
 * ============================================================================
 * === Backwards compatibility defines
 * ============================================================================
 */

#define mpack_write_int      mpack_write_integer
#define mpack_write_sint     mpack_write_integer
#define mpack_write_sinteger mpack_write_integer
#define mpack_write_uint     mpack_write_uinteger
#define mpack_read_sinteger  mpack_read_integer

#include "libtypes.h"
#include "libstream.h"

static inline bool mpack_stream_reader(mpack_ctx_t * ctx, void *data, size_t size)
{
    return stream_read((stream_t *) ctx->buf, (char *)data, size) == size;
}

static inline size_t mpack_stream_writer(mpack_ctx_t * ctx, const void *data, size_t size)
{
    return stream_write((stream_t *) ctx->buf, (char *)data, size) == size;
}

void mpack_ctx_dump(stream_t *output, mpack_ctx_t *ctx, int formated);
bool mpack_read_range(mpack_ctx_t *ctx, var_range_t *range);
bool mpack_write_range(mpack_ctx_t *ctx, var_range_t *range);
bool mpack_read_multi_range(mpack_ctx_t *ctx, var_multi_range_t *mrange);
bool mpack_write_multi_range(mpack_ctx_t *ctx, var_multi_range_t *mrange);

#endif
