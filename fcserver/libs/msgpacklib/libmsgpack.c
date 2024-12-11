#include "libmsgpack.h"
#include "libendian.h"

#include <ctype.h>
#include <inttypes.h>

static const uint32_t version = 14;
static const uint32_t mp_version = 5;

enum
{
    POSITIVE_FIXNUM_MARKER = 0x00,
    FIXMAP_MARKER = 0x80,
    FIXARRAY_MARKER = 0x90,
    FIXSTR_MARKER = 0xA0,
    NIL_MARKER = 0xC0,
    FALSE_MARKER = 0xC2,
    TRUE_MARKER = 0xC3,
    BIN8_MARKER = 0xC4,
    BIN16_MARKER = 0xC5,
    BIN32_MARKER = 0xC6,
    EXT8_MARKER = 0xC7,
    EXT16_MARKER = 0xC8,
    EXT32_MARKER = 0xC9,
    FLOAT_MARKER = 0xCA,
    DOUBLE_MARKER = 0xCB,
    U8_MARKER = 0xCC,
    U16_MARKER = 0xCD,
    U32_MARKER = 0xCE,
    U64_MARKER = 0xCF,
    S8_MARKER = 0xD0,
    S16_MARKER = 0xD1,
    S32_MARKER = 0xD2,
    S64_MARKER = 0xD3,
    FIXEXT1_MARKER = 0xD4,
    FIXEXT2_MARKER = 0xD5,
    FIXEXT4_MARKER = 0xD6,
    FIXEXT8_MARKER = 0xD7,
    FIXEXT16_MARKER = 0xD8,
    STR8_MARKER = 0xD9,
    STR16_MARKER = 0xDA,
    STR32_MARKER = 0xDB,
    ARRAY16_MARKER = 0xDC,
    ARRAY32_MARKER = 0xDD,
    MAP16_MARKER = 0xDE,
    MAP32_MARKER = 0xDF,
    NEGATIVE_FIXNUM_MARKER = 0xE0
};

enum
{
    FIXARRAY_SIZE = 0xF,
    FIXMAP_SIZE = 0xF,
    FIXSTR_SIZE = 0x1F
};

enum
{
    ERROR_NONE,
    STR_DATA_LENGTH_TOO_LONG_ERROR,
    BIN_DATA_LENGTH_TOO_LONG_ERROR,
    ARRAY_LENGTH_TOO_LONG_ERROR,
    MAP_LENGTH_TOO_LONG_ERROR,
    INPUT_VALUE_TOO_LARGE_ERROR,
    FIXED_VALUE_WRITING_ERROR,
    TYPE_MARKER_READING_ERROR,
    TYPE_MARKER_WRITING_ERROR,
    DATA_READING_ERROR,
    DATA_WRITING_ERROR,
    EXT_TYPE_READING_ERROR,
    EXT_TYPE_WRITING_ERROR,
    INVALID_TYPE_ERROR,
    LENGTH_READING_ERROR,
    LENGTH_WRITING_ERROR,
    ERROR_MAX
};

const char* mpack_error_messages[ERROR_MAX + 1] = {
    "No Error",
    "Specified string data length is too long (> 0xFFFFFFFF)",
    "Specified binary data length is too long (> 0xFFFFFFFF)",
    "Specified array length is too long (> 0xFFFFFFFF)",
    "Specified map length is too long (> 0xFFFFFFFF)",
    "Input value is too large",
    "Error writing fixed value",
    "Error reading type marker",
    "Error writing type marker",
    "Error reading packed data",
    "Error writing packed data",
    "Error reading ext type",
    "Error writing ext type",
    "Invalid type",
    "Error reading size",
    "Error writing size",
    "Max Error"};

static bool read_byte(mpack_ctx_t* ctx, uint8_t* x)
{
    return ctx->read(ctx, x, sizeof(uint8_t));
}

static bool write_byte(mpack_ctx_t* ctx, uint8_t x)
{
    return (ctx->write(ctx, &x, sizeof(uint8_t)) == (sizeof(uint8_t)));
}

static bool read_type_marker(mpack_ctx_t* ctx, uint8_t* marker)
{
    if (read_byte(ctx, marker))
        return true;

    ctx->error = TYPE_MARKER_READING_ERROR;
    return false;
}

static bool write_type_marker(mpack_ctx_t* ctx, uint8_t marker)
{
    if (write_byte(ctx, marker))
        return true;

    ctx->error = TYPE_MARKER_WRITING_ERROR;
    return false;
}

static bool write_fixed_value(mpack_ctx_t* ctx, uint8_t value)
{
    if (write_byte(ctx, value))
        return true;

    ctx->error = FIXED_VALUE_WRITING_ERROR;
    return false;
}

void mpack_init(mpack_ctx_t* ctx, void* buf, mpack_reader_t read,
                mpack_writer_t write)
{
    ctx->error = ERROR_NONE;
    ctx->buf = buf;
    ctx->read = read;
    ctx->write = write;
}

uint32_t mpack_version(void) { return version; }

uint32_t mpack_mp_version(void) { return mp_version; }

const char* mpack_strerror(mpack_ctx_t* ctx)
{
    if (ctx->error > ERROR_NONE && ctx->error < ERROR_MAX)
        return mpack_error_messages[ctx->error];

    return "";
}

bool mpack_write_pfix(mpack_ctx_t* ctx, uint8_t c)
{
    if (c <= 0x7F)
        return write_fixed_value(ctx, c);

    ctx->error = INPUT_VALUE_TOO_LARGE_ERROR;
    return false;
}

bool mpack_write_nfix(mpack_ctx_t* ctx, int8_t c)
{
    if (c >= -32 && c <= -1)
        return write_fixed_value(ctx, c);

    ctx->error = INPUT_VALUE_TOO_LARGE_ERROR;
    return false;
}

bool mpack_write_sfix(mpack_ctx_t* ctx, int8_t c)
{
    if (c >= 0)
        return mpack_write_pfix(ctx, c);
    if (c >= -32 && c <= -1)
        return mpack_write_nfix(ctx, c);

    ctx->error = INPUT_VALUE_TOO_LARGE_ERROR;
    return false;
}

bool mpack_write_s8(mpack_ctx_t* ctx, int8_t c)
{
    if (!write_type_marker(ctx, S8_MARKER))
        return false;

    return ctx->write(ctx, &c, sizeof(int8_t));
}

bool mpack_write_s16(mpack_ctx_t* ctx, int16_t s)
{
    if (!write_type_marker(ctx, S16_MARKER))
        return false;

    s = endian_htons(s);

    return ctx->write(ctx, &s, sizeof(int16_t));
}

bool mpack_write_s32(mpack_ctx_t* ctx, int32_t i)
{
    if (!write_type_marker(ctx, S32_MARKER))
        return false;

    i = endian_htonl(i);

    return ctx->write(ctx, &i, sizeof(int32_t));
}

bool mpack_write_s64(mpack_ctx_t* ctx, int64_t l)
{
    if (!write_type_marker(ctx, S64_MARKER))
        return false;

    l = endian_htonll(l);

    return ctx->write(ctx, &l, sizeof(int64_t));
}

bool mpack_write_integer(mpack_ctx_t* ctx, int64_t d)
{
    if (d >= 0)
        return mpack_write_uinteger(ctx, d);
    if (d >= -32)
        return mpack_write_nfix(ctx, (int8_t)d);
    if (d >= -128)
        return mpack_write_s8(ctx, (int8_t)d);
    if (d >= -32768)
        return mpack_write_s16(ctx, (int16_t)d);
    if (d >= (-2147483647 - 1))
        return mpack_write_s32(ctx, (int32_t)d);

    return mpack_write_s64(ctx, d);
}

bool mpack_write_ufix(mpack_ctx_t* ctx, uint8_t c)
{
    return mpack_write_pfix(ctx, c);
}

bool mpack_write_u8(mpack_ctx_t* ctx, uint8_t c)
{
    if (!write_type_marker(ctx, U8_MARKER))
        return false;

    return ctx->write(ctx, &c, sizeof(uint8_t));
}

bool mpack_write_u16(mpack_ctx_t* ctx, uint16_t s)
{
    if (!write_type_marker(ctx, U16_MARKER))
        return false;

    s = endian_htons(s);

    return ctx->write(ctx, &s, sizeof(uint16_t));
}

bool mpack_write_u32(mpack_ctx_t* ctx, uint32_t i)
{
    if (!write_type_marker(ctx, U32_MARKER))
        return false;

    i = endian_htonl(i);

    return ctx->write(ctx, &i, sizeof(uint32_t));
}

bool mpack_write_u64(mpack_ctx_t* ctx, uint64_t l)
{
    if (!write_type_marker(ctx, U64_MARKER))
        return false;

    l = endian_htonll(l);

    return ctx->write(ctx, &l, sizeof(uint64_t));
}

bool mpack_write_uinteger(mpack_ctx_t* ctx, uint64_t u)
{
    if (u <= 0x7F)
        return mpack_write_pfix(ctx, (uint8_t)u);
    if (u <= 0xFF)
        return mpack_write_u8(ctx, (uint8_t)u);
    if (u <= 0xFFFF)
        return mpack_write_u16(ctx, (uint16_t)u);
    if (u <= 0xFFFFFFFF)
        return mpack_write_u32(ctx, (uint32_t)u);

    return mpack_write_u64(ctx, u);
}

bool mpack_write_float(mpack_ctx_t* ctx, float f)
{
    if (!write_type_marker(ctx, FLOAT_MARKER))
        return false;

    f = endian_htonl(f);

    return ctx->write(ctx, &f, sizeof(float));
}

bool mpack_write_double(mpack_ctx_t* ctx, double d)
{
    if (!write_type_marker(ctx, DOUBLE_MARKER))
        return false;

    d = endian_htonll(d);

    return ctx->write(ctx, &d, sizeof(double));
}

bool mpack_write_decimal(mpack_ctx_t* ctx, double d)
{
    float f = (float)d;
    float df = (double)f;

    if (df == d)
        return mpack_write_float(ctx, f);
    else
        return mpack_write_double(ctx, d);
}

bool mpack_write_nil(mpack_ctx_t* ctx)
{
    return write_type_marker(ctx, NIL_MARKER);
}

bool mpack_write_true(mpack_ctx_t* ctx)
{
    return write_type_marker(ctx, TRUE_MARKER);
}

bool mpack_write_false(mpack_ctx_t* ctx)
{
    return write_type_marker(ctx, FALSE_MARKER);
}

bool mpack_write_bool(mpack_ctx_t* ctx, bool b)
{
    if (b)
        return mpack_write_true(ctx);

    return mpack_write_false(ctx);
}

bool mpack_write_u8_as_bool(mpack_ctx_t* ctx, uint8_t b)
{
    if (b)
        return mpack_write_true(ctx);

    return mpack_write_false(ctx);
}

bool mpack_write_fixstr_marker(mpack_ctx_t* ctx, uint8_t size)
{
    if (size <= FIXSTR_SIZE)
        return write_fixed_value(ctx, FIXSTR_MARKER | size);

    ctx->error = INPUT_VALUE_TOO_LARGE_ERROR;
    return false;
}

bool mpack_write_fixstr(mpack_ctx_t* ctx, const char* data, uint8_t size)
{
    if (!mpack_write_fixstr_marker(ctx, size))
        return false;

    if (size == 0)
        return true;

    if (ctx->write(ctx, data, size))
        return true;

    ctx->error = DATA_WRITING_ERROR;
    return false;
}

bool mpack_write_str8_marker(mpack_ctx_t* ctx, uint8_t size)
{
    if (!write_type_marker(ctx, STR8_MARKER))
        return false;

    if (ctx->write(ctx, &size, sizeof(uint8_t)))
        return true;

    ctx->error = LENGTH_WRITING_ERROR;
    return false;
}

bool mpack_write_str8(mpack_ctx_t* ctx, const char* data, uint8_t size)
{
    if (!mpack_write_str8_marker(ctx, size))
        return false;

    if (size == 0)
        return true;

    if (ctx->write(ctx, data, size))
        return true;

    ctx->error = DATA_WRITING_ERROR;
    return false;
}

bool mpack_write_str16_marker(mpack_ctx_t* ctx, uint16_t size)
{
    if (!write_type_marker(ctx, STR16_MARKER))
        return false;

    size = endian_htons(size);

    if (ctx->write(ctx, &size, sizeof(uint16_t)))
        return true;

    ctx->error = LENGTH_WRITING_ERROR;
    return false;
}

bool mpack_write_str16(mpack_ctx_t* ctx, const char* data, uint16_t size)
{
    if (!mpack_write_str16_marker(ctx, size))
        return false;

    if (size == 0)
        return true;

    if (ctx->write(ctx, data, size))
        return true;

    ctx->error = DATA_WRITING_ERROR;
    return false;
}

bool mpack_write_str32_marker(mpack_ctx_t* ctx, uint32_t size)
{
    if (!write_type_marker(ctx, STR32_MARKER))
        return false;

    size = endian_htonl(size);

    if (ctx->write(ctx, &size, sizeof(uint32_t)))
        return true;

    ctx->error = LENGTH_WRITING_ERROR;
    return false;
}

bool mpack_write_str32(mpack_ctx_t* ctx, const char* data, uint32_t size)
{
    if (!mpack_write_str32_marker(ctx, size))
        return false;

    if (size == 0)
        return true;

    if (ctx->write(ctx, data, size))
        return true;

    ctx->error = DATA_WRITING_ERROR;
    return false;
}

bool mpack_write_str_marker(mpack_ctx_t* ctx, uint32_t size)
{
    if (size <= FIXSTR_SIZE)
        return mpack_write_fixstr_marker(ctx, (uint8_t)size);
    if (size <= 0xFF)
        return mpack_write_str8_marker(ctx, (uint8_t)size);
    if (size <= 0xFFFF)
        return mpack_write_str16_marker(ctx, (uint16_t)size);

    return mpack_write_str32_marker(ctx, size);
}

bool mpack_write_str_marker_v4(mpack_ctx_t* ctx, uint32_t size)
{
    if (size <= FIXSTR_SIZE)
        return mpack_write_fixstr_marker(ctx, (uint8_t)size);
    if (size <= 0xFFFF)
        return mpack_write_str16_marker(ctx, (uint16_t)size);

    return mpack_write_str32_marker(ctx, size);
}

bool mpack_write_str_for_snmp(mpack_ctx_t* ctx, const char* data, uint32_t size)
{
    if (ctx->write(ctx, data, size))
    {
        return true;
    }
    return false;
}

bool mpack_write_str(mpack_ctx_t* ctx, const char* data, uint32_t size)
{
    if (size <= FIXSTR_SIZE)
        return mpack_write_fixstr(ctx, data, (uint8_t)size);
    if (size <= 0xFF)
        return mpack_write_str8(ctx, data, (uint8_t)size);
    if (size <= 0xFFFF)
        return mpack_write_str16(ctx, data, (uint16_t)size);

    return mpack_write_str32(ctx, data, size);
}

bool mpack_write_fmt(mpack_ctx_t* ctx, const char* fmt, ...)
{
    int ret;
    va_list valist;
    char* str = NULL;

    va_start(valist, fmt);
    ret = vasprintf(&str, fmt, valist);
    va_end(valist);
    if (ret < 0)
    {
        ctx->error = DATA_WRITING_ERROR;
        return false;
    }

    ret = mpack_write_str(ctx, str, ret);
    free(str);
    return ret;
}

bool mpack_write_str_v4(mpack_ctx_t* ctx, const char* data, uint32_t size)
{
    if (size <= FIXSTR_SIZE)
        return mpack_write_fixstr(ctx, data, (uint8_t)size);
    if (size <= 0xFFFF)
        return mpack_write_str16(ctx, data, (uint16_t)size);

    return mpack_write_str32(ctx, data, size);
}

bool mpack_write_bin8_marker(mpack_ctx_t* ctx, uint8_t size)
{
    if (!write_type_marker(ctx, BIN8_MARKER))
        return false;

    if (ctx->write(ctx, &size, sizeof(uint8_t)))
        return true;

    ctx->error = LENGTH_WRITING_ERROR;
    return false;
}

bool mpack_write_bin8(mpack_ctx_t* ctx, const void* data, uint8_t size)
{
    if (!mpack_write_bin8_marker(ctx, size))
        return false;

    if (size == 0)
        return true;

    if (ctx->write(ctx, data, size))
        return true;

    ctx->error = DATA_WRITING_ERROR;
    return false;
}

bool mpack_write_bin16_marker(mpack_ctx_t* ctx, uint16_t size)
{
    if (!write_type_marker(ctx, BIN16_MARKER))
        return false;

    size = endian_htons(size);

    if (ctx->write(ctx, &size, sizeof(uint16_t)))
        return true;

    ctx->error = LENGTH_WRITING_ERROR;
    return false;
}

bool mpack_write_bin16(mpack_ctx_t* ctx, const void* data, uint16_t size)
{
    if (!mpack_write_bin16_marker(ctx, size))
        return false;

    if (size == 0)
        return true;

    if (ctx->write(ctx, data, size))
        return true;

    ctx->error = DATA_WRITING_ERROR;
    return false;
}

bool mpack_write_bin32_marker(mpack_ctx_t* ctx, uint32_t size)
{
    if (!write_type_marker(ctx, BIN32_MARKER))
        return false;

    size = endian_htonl(size);

    if (ctx->write(ctx, &size, sizeof(uint32_t)))
        return true;

    ctx->error = LENGTH_WRITING_ERROR;
    return false;
}

bool mpack_write_bin32(mpack_ctx_t* ctx, const void* data, uint32_t size)
{
    if (!mpack_write_bin32_marker(ctx, size))
        return false;

    if (size == 0)
        return true;

    if (ctx->write(ctx, data, size))
        return true;

    ctx->error = DATA_WRITING_ERROR;
    return false;
}

bool mpack_write_bin_marker(mpack_ctx_t* ctx, uint32_t size)
{
    if (size <= 0xFF)
        return mpack_write_bin8_marker(ctx, (uint8_t)size);
    if (size <= 0xFFFF)
        return mpack_write_bin16_marker(ctx, (uint16_t)size);

    return mpack_write_bin32_marker(ctx, size);
}

bool mpack_write_bin(mpack_ctx_t* ctx, const void* data, uint32_t size)
{
    if (size <= 0xFF)
        return mpack_write_bin8(ctx, data, (uint8_t)size);
    if (size <= 0xFFFF)
        return mpack_write_bin16(ctx, data, (uint16_t)size);

    return mpack_write_bin32(ctx, data, size);
}

bool mpack_write_fixarray(mpack_ctx_t* ctx, uint8_t size)
{
    if (size <= FIXARRAY_SIZE)
        return write_fixed_value(ctx, FIXARRAY_MARKER | size);

    ctx->error = INPUT_VALUE_TOO_LARGE_ERROR;
    return false;
}

bool mpack_write_array16(mpack_ctx_t* ctx, uint16_t size)
{
    if (!write_type_marker(ctx, ARRAY16_MARKER))
        return false;

    size = endian_htons(size);

    if (ctx->write(ctx, &size, sizeof(uint16_t)))
        return true;

    ctx->error = LENGTH_WRITING_ERROR;
    return false;
}

bool mpack_write_array32(mpack_ctx_t* ctx, uint32_t size)
{
    if (!write_type_marker(ctx, ARRAY32_MARKER))
        return false;

    size = endian_htonl(size);

    if (ctx->write(ctx, &size, sizeof(uint32_t)))
        return true;

    ctx->error = LENGTH_WRITING_ERROR;
    return false;
}

bool mpack_write_array(mpack_ctx_t* ctx, uint32_t size)
{
    if (size <= FIXARRAY_SIZE)
        return mpack_write_fixarray(ctx, (uint8_t)size);
    if (size <= 0xFFFF)
        return mpack_write_array16(ctx, (uint16_t)size);

    return mpack_write_array32(ctx, size);
}

bool mpack_write_fixmap(mpack_ctx_t* ctx, uint8_t size)
{
    if (size <= FIXMAP_SIZE)
        return write_fixed_value(ctx, FIXMAP_MARKER | size);

    ctx->error = INPUT_VALUE_TOO_LARGE_ERROR;
    return false;
}

bool mpack_write_map16(mpack_ctx_t* ctx, uint16_t size)
{
    if (!write_type_marker(ctx, MAP16_MARKER))
        return false;

    size = endian_htons(size);

    if (ctx->write(ctx, &size, sizeof(uint16_t)))
        return true;

    ctx->error = LENGTH_WRITING_ERROR;
    return false;
}

bool mpack_write_map32(mpack_ctx_t* ctx, uint32_t size)
{
    if (!write_type_marker(ctx, MAP32_MARKER))
        return false;

    size = endian_htonl(size);

    if (ctx->write(ctx, &size, sizeof(uint32_t)))
        return true;

    ctx->error = LENGTH_WRITING_ERROR;
    return false;
}

bool mpack_write_map(mpack_ctx_t* ctx, uint32_t size)
{
    if (size <= FIXMAP_SIZE)
        return mpack_write_fixmap(ctx, (uint8_t)size);
    if (size <= 0xFFFF)
        return mpack_write_map16(ctx, (uint16_t)size);

    return mpack_write_map32(ctx, size);
}

bool mpack_write_fixext1_marker(mpack_ctx_t* ctx, int8_t type)
{
    if (!write_type_marker(ctx, FIXEXT1_MARKER))
        return false;

    if (ctx->write(ctx, &type, sizeof(int8_t)))
        return true;

    ctx->error = EXT_TYPE_WRITING_ERROR;
    return false;
}

bool mpack_write_fixext1(mpack_ctx_t* ctx, int8_t type, const void* data)
{
    if (!mpack_write_fixext1_marker(ctx, type))
        return false;

    if (ctx->write(ctx, data, 1))
        return true;

    ctx->error = DATA_WRITING_ERROR;
    return false;
}

bool mpack_write_fixext2_marker(mpack_ctx_t* ctx, int8_t type)
{
    if (!write_type_marker(ctx, FIXEXT2_MARKER))
        return false;

    if (ctx->write(ctx, &type, sizeof(int8_t)))
        return true;

    ctx->error = EXT_TYPE_WRITING_ERROR;
    return false;
}

bool mpack_write_fixext2(mpack_ctx_t* ctx, int8_t type, const void* data)
{
    if (!mpack_write_fixext2_marker(ctx, type))
        return false;

    if (ctx->write(ctx, data, 2))
        return true;

    ctx->error = DATA_WRITING_ERROR;
    return false;
}

bool mpack_write_fixext4_marker(mpack_ctx_t* ctx, int8_t type)
{
    if (!write_type_marker(ctx, FIXEXT4_MARKER))
        return false;

    if (ctx->write(ctx, &type, sizeof(int8_t)))
        return true;

    ctx->error = EXT_TYPE_WRITING_ERROR;
    return false;
}

bool mpack_write_fixext4(mpack_ctx_t* ctx, int8_t type, const void* data)
{
    if (!mpack_write_fixext4_marker(ctx, type))
        return false;

    if (ctx->write(ctx, data, 4))
        return true;

    ctx->error = DATA_WRITING_ERROR;
    return false;
}

bool mpack_write_fixext8_marker(mpack_ctx_t* ctx, int8_t type)
{
    if (!write_type_marker(ctx, FIXEXT8_MARKER))
        return false;

    if (ctx->write(ctx, &type, sizeof(int8_t)))
        return true;

    ctx->error = EXT_TYPE_WRITING_ERROR;
    return false;
}

bool mpack_write_fixext8(mpack_ctx_t* ctx, int8_t type, const void* data)
{
    if (!mpack_write_fixext8_marker(ctx, type))
        return false;

    if (ctx->write(ctx, data, 8))
        return true;

    ctx->error = DATA_WRITING_ERROR;
    return false;
}

bool mpack_write_fixext16_marker(mpack_ctx_t* ctx, int8_t type)
{
    if (!write_type_marker(ctx, FIXEXT16_MARKER))
        return false;

    if (ctx->write(ctx, &type, sizeof(int8_t)))
        return true;

    ctx->error = EXT_TYPE_WRITING_ERROR;
    return false;
}

bool mpack_write_fixext16(mpack_ctx_t* ctx, int8_t type, const void* data)
{
    if (!mpack_write_fixext16_marker(ctx, type))
        return false;

    if (ctx->write(ctx, data, 16))
        return true;

    ctx->error = DATA_WRITING_ERROR;
    return false;
}

bool mpack_write_ext8_marker(mpack_ctx_t* ctx, int8_t type, uint8_t size)
{
    if (!write_type_marker(ctx, EXT8_MARKER))
        return false;

    if (!ctx->write(ctx, &size, sizeof(uint8_t)))
    {
        ctx->error = LENGTH_WRITING_ERROR;
        return false;
    }

    if (ctx->write(ctx, &type, sizeof(int8_t)))
        return true;

    ctx->error = EXT_TYPE_WRITING_ERROR;
    return false;
}

bool mpack_write_ext8(mpack_ctx_t* ctx, int8_t tp, uint8_t sz, const void* data)
{
    if (!mpack_write_ext8_marker(ctx, tp, sz))
        return false;

    if (ctx->write(ctx, data, sz))
        return true;

    ctx->error = DATA_WRITING_ERROR;
    return false;
}

bool mpack_write_ext16_marker(mpack_ctx_t* ctx, int8_t type, uint16_t size)
{
    if (!write_type_marker(ctx, EXT16_MARKER))
        return false;

    size = endian_htons(size);

    if (!ctx->write(ctx, &size, sizeof(uint16_t)))
    {
        ctx->error = LENGTH_WRITING_ERROR;
        return false;
    }

    if (ctx->write(ctx, &type, sizeof(int8_t)))
        return true;

    ctx->error = EXT_TYPE_WRITING_ERROR;
    return false;
}

bool mpack_write_ext16(mpack_ctx_t* ctx, int8_t tp, uint16_t sz,
                       const void* data)
{
    if (!mpack_write_ext16_marker(ctx, tp, sz))
        return false;

    if (ctx->write(ctx, data, sz))
        return true;

    ctx->error = DATA_WRITING_ERROR;
    return false;
}

bool mpack_write_ext32_marker(mpack_ctx_t* ctx, int8_t type, uint32_t size)
{
    if (!write_type_marker(ctx, EXT32_MARKER))
        return false;

    size = endian_htonl(size);

    if (!ctx->write(ctx, &size, sizeof(uint32_t)))
    {
        ctx->error = LENGTH_WRITING_ERROR;
        return false;
    }

    if (ctx->write(ctx, &type, sizeof(int8_t)))
        return true;

    ctx->error = EXT_TYPE_WRITING_ERROR;
    return false;
}

bool mpack_write_ext32(mpack_ctx_t* ctx, int8_t tp, uint32_t sz,
                       const void* data)
{
    if (!mpack_write_ext32_marker(ctx, tp, sz))
        return false;

    if (ctx->write(ctx, data, sz))
        return true;

    ctx->error = DATA_WRITING_ERROR;
    return false;
}

bool mpack_write_ext_marker(mpack_ctx_t* ctx, int8_t tp, uint32_t sz)
{
    if (sz == 1)
        return mpack_write_fixext1_marker(ctx, tp);
    if (sz == 2)
        return mpack_write_fixext2_marker(ctx, tp);
    if (sz == 4)
        return mpack_write_fixext4_marker(ctx, tp);
    if (sz == 8)
        return mpack_write_fixext8_marker(ctx, tp);
    if (sz == 16)
        return mpack_write_fixext16_marker(ctx, tp);
    if (sz <= 0xFF)
        return mpack_write_ext8_marker(ctx, tp, (uint8_t)sz);
    if (sz <= 0xFFFF)
        return mpack_write_ext16_marker(ctx, tp, (uint16_t)sz);

    return mpack_write_ext32_marker(ctx, tp, sz);
}

bool mpack_write_ext(mpack_ctx_t* ctx, int8_t tp, uint32_t sz, const void* data)
{
    if (sz == 1)
        return mpack_write_fixext1(ctx, tp, data);
    if (sz == 2)
        return mpack_write_fixext2(ctx, tp, data);
    if (sz == 4)
        return mpack_write_fixext4(ctx, tp, data);
    if (sz == 8)
        return mpack_write_fixext8(ctx, tp, data);
    if (sz == 16)
        return mpack_write_fixext16(ctx, tp, data);
    if (sz <= 0xFF)
        return mpack_write_ext8(ctx, tp, (uint8_t)sz, data);
    if (sz <= 0xFFFF)
        return mpack_write_ext16(ctx, tp, (uint16_t)sz, data);

    return mpack_write_ext32(ctx, tp, sz, data);
}

bool mpack_write_object(mpack_ctx_t* ctx, mpack_object_t* obj)
{
    switch (obj->type)
    {
        case MPACK_TYPE_POSITIVE_FIXNUM:
            return mpack_write_pfix(ctx, obj->as.u8);
        case MPACK_TYPE_FIXMAP:
            return mpack_write_fixmap(ctx, (uint8_t)obj->as.map_size);
        case MPACK_TYPE_FIXARRAY:
            return mpack_write_fixarray(ctx, (uint8_t)obj->as.array_size);
        case MPACK_TYPE_FIXSTR:
            return mpack_write_fixstr_marker(ctx, (uint8_t)obj->as.str_size);
        case MPACK_TYPE_NIL:
            return mpack_write_nil(ctx);
        case MPACK_TYPE_BOOLEAN:
            if (obj->as.boolean)
                return mpack_write_true(ctx);
            return mpack_write_false(ctx);
        case MPACK_TYPE_BIN8:
            return mpack_write_bin8_marker(ctx, (uint8_t)obj->as.bin_size);
        case MPACK_TYPE_BIN16:
            return mpack_write_bin16_marker(ctx, (uint16_t)obj->as.bin_size);
        case MPACK_TYPE_BIN32:
            return mpack_write_bin32_marker(ctx, obj->as.bin_size);
        case MPACK_TYPE_EXT8:
            return mpack_write_ext8_marker(ctx, obj->as.ext.type,
                                           (uint8_t)obj->as.ext.size);
        case MPACK_TYPE_EXT16:
            return mpack_write_ext16_marker(ctx, obj->as.ext.type,
                                            (uint16_t)obj->as.ext.size);
        case MPACK_TYPE_EXT32:
            return mpack_write_ext32_marker(ctx, obj->as.ext.type,
                                            obj->as.ext.size);
        case MPACK_TYPE_FLOAT:
            return mpack_write_float(ctx, obj->as.flt);
        case MPACK_TYPE_DOUBLE:
            return mpack_write_double(ctx, obj->as.dbl);
        case MPACK_TYPE_UINT8:
            return mpack_write_u8(ctx, obj->as.u8);
        case MPACK_TYPE_UINT16:
            return mpack_write_u16(ctx, obj->as.u16);
        case MPACK_TYPE_UINT32:
            return mpack_write_u32(ctx, obj->as.u32);
        case MPACK_TYPE_UINT64:
            return mpack_write_u64(ctx, obj->as.u64);
        case MPACK_TYPE_SINT8:
            return mpack_write_s8(ctx, obj->as.s8);
        case MPACK_TYPE_SINT16:
            return mpack_write_s16(ctx, obj->as.s16);
        case MPACK_TYPE_SINT32:
            return mpack_write_s32(ctx, obj->as.s32);
        case MPACK_TYPE_SINT64:
            return mpack_write_s64(ctx, obj->as.s64);
        case MPACK_TYPE_FIXEXT1:
            return mpack_write_fixext1_marker(ctx, obj->as.ext.type);
        case MPACK_TYPE_FIXEXT2:
            return mpack_write_fixext2_marker(ctx, obj->as.ext.type);
        case MPACK_TYPE_FIXEXT4:
            return mpack_write_fixext4_marker(ctx, obj->as.ext.type);
        case MPACK_TYPE_FIXEXT8:
            return mpack_write_fixext8_marker(ctx, obj->as.ext.type);
        case MPACK_TYPE_FIXEXT16:
            return mpack_write_fixext16_marker(ctx, obj->as.ext.type);
        case MPACK_TYPE_STR8:
            return mpack_write_str8_marker(ctx, (uint8_t)obj->as.str_size);
        case MPACK_TYPE_STR16:
            return mpack_write_str16_marker(ctx, (uint16_t)obj->as.str_size);
        case MPACK_TYPE_STR32:
            return mpack_write_str32_marker(ctx, obj->as.str_size);
        case MPACK_TYPE_ARRAY16:
            return mpack_write_array16(ctx, (uint16_t)obj->as.array_size);
        case MPACK_TYPE_ARRAY32:
            return mpack_write_array32(ctx, obj->as.array_size);
        case MPACK_TYPE_MAP16:
            return mpack_write_map16(ctx, (uint16_t)obj->as.map_size);
        case MPACK_TYPE_MAP32:
            return mpack_write_map32(ctx, obj->as.map_size);
        case MPACK_TYPE_NEGATIVE_FIXNUM:
            return mpack_write_nfix(ctx, obj->as.s8);
        default:
            ctx->error = INVALID_TYPE_ERROR;
            return false;
    }
}

bool mpack_write_object_v4(mpack_ctx_t* ctx, mpack_object_t* obj)
{
    switch (obj->type)
    {
        case MPACK_TYPE_POSITIVE_FIXNUM:
            return mpack_write_pfix(ctx, obj->as.u8);
        case MPACK_TYPE_FIXMAP:
            return mpack_write_fixmap(ctx, (uint8_t)obj->as.map_size);
        case MPACK_TYPE_FIXARRAY:
            return mpack_write_fixarray(ctx, (uint8_t)obj->as.array_size);
        case MPACK_TYPE_FIXSTR:
            return mpack_write_fixstr_marker(ctx, (uint8_t)obj->as.str_size);
        case MPACK_TYPE_NIL:
            return mpack_write_nil(ctx);
        case MPACK_TYPE_BOOLEAN:
            if (obj->as.boolean)
                return mpack_write_true(ctx);
            return mpack_write_false(ctx);
        case MPACK_TYPE_BIN8:
            return mpack_write_bin8_marker(ctx, (uint8_t)obj->as.bin_size);
        case MPACK_TYPE_BIN16:
            return mpack_write_bin16_marker(ctx, (uint16_t)obj->as.bin_size);
        case MPACK_TYPE_BIN32:
            return mpack_write_bin32_marker(ctx, obj->as.bin_size);
        case MPACK_TYPE_EXT8:
            return mpack_write_ext8_marker(ctx, obj->as.ext.type,
                                           (uint8_t)obj->as.ext.size);
        case MPACK_TYPE_EXT16:
            return mpack_write_ext16_marker(ctx, obj->as.ext.type,
                                            (uint16_t)obj->as.ext.size);
        case MPACK_TYPE_EXT32:
            return mpack_write_ext32_marker(ctx, obj->as.ext.type,
                                            obj->as.ext.size);
        case MPACK_TYPE_FLOAT:
            return mpack_write_float(ctx, obj->as.flt);
        case MPACK_TYPE_DOUBLE:
            return mpack_write_double(ctx, obj->as.dbl);
        case MPACK_TYPE_UINT8:
            return mpack_write_u8(ctx, obj->as.u8);
        case MPACK_TYPE_UINT16:
            return mpack_write_u16(ctx, obj->as.u16);
        case MPACK_TYPE_UINT32:
            return mpack_write_u32(ctx, obj->as.u32);
        case MPACK_TYPE_UINT64:
            return mpack_write_u64(ctx, obj->as.u64);
        case MPACK_TYPE_SINT8:
            return mpack_write_s8(ctx, obj->as.s8);
        case MPACK_TYPE_SINT16:
            return mpack_write_s16(ctx, obj->as.s16);
        case MPACK_TYPE_SINT32:
            return mpack_write_s32(ctx, obj->as.s32);
        case MPACK_TYPE_SINT64:
            return mpack_write_s64(ctx, obj->as.s64);
        case MPACK_TYPE_FIXEXT1:
            return mpack_write_fixext1_marker(ctx, obj->as.ext.type);
        case MPACK_TYPE_FIXEXT2:
            return mpack_write_fixext2_marker(ctx, obj->as.ext.type);
        case MPACK_TYPE_FIXEXT4:
            return mpack_write_fixext4_marker(ctx, obj->as.ext.type);
        case MPACK_TYPE_FIXEXT8:
            return mpack_write_fixext8_marker(ctx, obj->as.ext.type);
        case MPACK_TYPE_FIXEXT16:
            return mpack_write_fixext16_marker(ctx, obj->as.ext.type);
        case MPACK_TYPE_STR16:
            return mpack_write_str16_marker(ctx, (uint16_t)obj->as.str_size);
        case MPACK_TYPE_STR32:
            return mpack_write_str32_marker(ctx, obj->as.str_size);
        case MPACK_TYPE_ARRAY16:
            return mpack_write_array16(ctx, (uint16_t)obj->as.array_size);
        case MPACK_TYPE_ARRAY32:
            return mpack_write_array32(ctx, obj->as.array_size);
        case MPACK_TYPE_MAP16:
            return mpack_write_map16(ctx, (uint16_t)obj->as.map_size);
        case MPACK_TYPE_MAP32:
            return mpack_write_map32(ctx, obj->as.map_size);
        case MPACK_TYPE_NEGATIVE_FIXNUM:
            return mpack_write_nfix(ctx, obj->as.s8);
        default:
            ctx->error = INVALID_TYPE_ERROR;
            return false;
    }
}

bool mpack_read_pfix(mpack_ctx_t* ctx, uint8_t* c)
{
    mpack_object_t obj;

    if (!mpack_read_object(ctx, &obj))
        return false;

    if (obj.type != MPACK_TYPE_POSITIVE_FIXNUM)
    {
        ctx->error = INVALID_TYPE_ERROR;
        return false;
    }

    *c = obj.as.u8;
    return true;
}

bool mpack_read_nfix(mpack_ctx_t* ctx, int8_t* c)
{
    mpack_object_t obj;

    if (!mpack_read_object(ctx, &obj))
        return false;

    if (obj.type != MPACK_TYPE_NEGATIVE_FIXNUM)
    {
        ctx->error = INVALID_TYPE_ERROR;
        return false;
    }

    *c = obj.as.s8;
    return true;
}

bool mpack_read_sfix(mpack_ctx_t* ctx, int8_t* c)
{
    mpack_object_t obj;

    if (!mpack_read_object(ctx, &obj))
        return false;

    switch (obj.type)
    {
        case MPACK_TYPE_POSITIVE_FIXNUM:
        case MPACK_TYPE_NEGATIVE_FIXNUM:
            *c = obj.as.s8;
            return true;
        default:
            ctx->error = INVALID_TYPE_ERROR;
            return false;
    }
}

bool mpack_read_s8(mpack_ctx_t* ctx, int8_t* c)
{
    mpack_object_t obj;

    if (!mpack_read_object(ctx, &obj))
        return false;

    if (obj.type != MPACK_TYPE_SINT8)
    {
        ctx->error = INVALID_TYPE_ERROR;
        return false;
    }

    *c = obj.as.s8;
    return true;
}

bool mpack_read_s16(mpack_ctx_t* ctx, int16_t* s)
{
    mpack_object_t obj;

    if (!mpack_read_object(ctx, &obj))
        return false;

    if (obj.type != MPACK_TYPE_SINT16)
    {
        ctx->error = INVALID_TYPE_ERROR;
        return false;
    }

    *s = obj.as.s16;
    return true;
}

bool mpack_read_s32(mpack_ctx_t* ctx, int32_t* i)
{
    mpack_object_t obj;

    if (!mpack_read_object(ctx, &obj))
        return false;

    if (obj.type != MPACK_TYPE_SINT32)
    {
        ctx->error = INVALID_TYPE_ERROR;
        return false;
    }

    *i = obj.as.s32;
    return true;
}

bool mpack_read_s64(mpack_ctx_t* ctx, int64_t* l)
{
    mpack_object_t obj;

    if (!mpack_read_object(ctx, &obj))
        return false;

    if (obj.type != MPACK_TYPE_SINT64)
    {
        ctx->error = INVALID_TYPE_ERROR;
        return false;
    }

    *l = obj.as.s64;
    return true;
}

bool mpack_read_char(mpack_ctx_t* ctx, int8_t* c)
{
    mpack_object_t obj;

    if (!mpack_read_object(ctx, &obj))
        return false;

    switch (obj.type)
    {
        case MPACK_TYPE_POSITIVE_FIXNUM:
        case MPACK_TYPE_NEGATIVE_FIXNUM:
        case MPACK_TYPE_SINT8:
            *c = obj.as.s8;
            return true;
        case MPACK_TYPE_UINT8:
            if (obj.as.u8 <= 127)
            {
                *c = obj.as.u8;
                return true;
            }
        default:
            ctx->error = INVALID_TYPE_ERROR;
            return false;
    }
}

bool mpack_read_short(mpack_ctx_t* ctx, int16_t* s)
{
    mpack_object_t obj;

    if (!mpack_read_object(ctx, &obj))
        return false;

    switch (obj.type)
    {
        case MPACK_TYPE_POSITIVE_FIXNUM:
        case MPACK_TYPE_NEGATIVE_FIXNUM:
        case MPACK_TYPE_SINT8:
            *s = obj.as.s8;
            return true;
        case MPACK_TYPE_UINT8:
            *s = obj.as.u8;
            return true;
        case MPACK_TYPE_SINT16:
            *s = obj.as.s16;
            return true;
        case MPACK_TYPE_UINT16:
            if (obj.as.u16 <= 32767)
            {
                *s = obj.as.u16;
                return true;
            }
        default:
            ctx->error = INVALID_TYPE_ERROR;
            return false;
    }
}

bool mpack_read_int(mpack_ctx_t* ctx, int32_t* i)
{
    mpack_object_t obj;

    if (!mpack_read_object(ctx, &obj))
        return false;

    switch (obj.type)
    {
        case MPACK_TYPE_POSITIVE_FIXNUM:
        case MPACK_TYPE_NEGATIVE_FIXNUM:
        case MPACK_TYPE_SINT8:
            *i = obj.as.s8;
            return true;
        case MPACK_TYPE_UINT8:
            *i = obj.as.u8;
            return true;
        case MPACK_TYPE_SINT16:
            *i = obj.as.s16;
            return true;
        case MPACK_TYPE_UINT16:
            *i = obj.as.u16;
            return true;
        case MPACK_TYPE_SINT32:
            *i = obj.as.s32;
            return true;
        case MPACK_TYPE_UINT32:
            if (obj.as.u32 <= 2147483647)
            {
                *i = obj.as.u32;
                return true;
            }
        default:
            ctx->error = INVALID_TYPE_ERROR;
            return false;
    }
}

bool mpack_read_long(mpack_ctx_t* ctx, int64_t* d)
{
    mpack_object_t obj;

    if (!mpack_read_object(ctx, &obj))
        return false;

    switch (obj.type)
    {
        case MPACK_TYPE_POSITIVE_FIXNUM:
        case MPACK_TYPE_NEGATIVE_FIXNUM:
        case MPACK_TYPE_SINT8:
            *d = obj.as.s8;
            return true;
        case MPACK_TYPE_UINT8:
            *d = obj.as.u8;
            return true;
        case MPACK_TYPE_SINT16:
            *d = obj.as.s16;
            return true;
        case MPACK_TYPE_UINT16:
            *d = obj.as.u16;
            return true;
        case MPACK_TYPE_SINT32:
            *d = obj.as.s32;
            return true;
        case MPACK_TYPE_UINT32:
            *d = obj.as.u32;
            return true;
        case MPACK_TYPE_SINT64:
            *d = obj.as.s64;
            return true;
        case MPACK_TYPE_UINT64:
            if (obj.as.u64 <= 9223372036854775807llu)
            {
                *d = obj.as.u64;
                return true;
            }
        default:
            ctx->error = INVALID_TYPE_ERROR;
            return false;
    }
}

bool mpack_read_integer(mpack_ctx_t* ctx, int64_t* d)
{
    return mpack_read_long(ctx, d);
}

bool mpack_read_ufix(mpack_ctx_t* ctx, uint8_t* c)
{
    return mpack_read_pfix(ctx, c);
}

bool mpack_read_u8(mpack_ctx_t* ctx, uint8_t* c)
{
    mpack_object_t obj;

    if (!mpack_read_object(ctx, &obj))
        return false;

    if (obj.type != MPACK_TYPE_UINT8)
    {
        ctx->error = INVALID_TYPE_ERROR;
        return false;
    }

    *c = obj.as.u8;
    return true;
}

bool mpack_read_u16(mpack_ctx_t* ctx, uint16_t* s)
{
    mpack_object_t obj;

    if (!mpack_read_object(ctx, &obj))
        return false;

    if (obj.type != MPACK_TYPE_UINT16)
    {
        ctx->error = INVALID_TYPE_ERROR;
        return false;
    }

    *s = obj.as.u16;
    return true;
}

bool mpack_read_u32(mpack_ctx_t* ctx, uint32_t* i)
{
    mpack_object_t obj;

    if (!mpack_read_object(ctx, &obj))
        return false;

    if (obj.type != MPACK_TYPE_UINT32)
    {
        ctx->error = INVALID_TYPE_ERROR;
        return false;
    }

    *i = obj.as.u32;
    return true;
}

bool mpack_read_u64(mpack_ctx_t* ctx, uint64_t* l)
{
    mpack_object_t obj;

    if (!mpack_read_object(ctx, &obj))
        return false;

    if (obj.type != MPACK_TYPE_UINT64)
    {
        ctx->error = INVALID_TYPE_ERROR;
        return false;
    }

    *l = obj.as.u64;
    return true;
}

bool mpack_read_uchar(mpack_ctx_t* ctx, uint8_t* c)
{
    mpack_object_t obj;

    if (!mpack_read_object(ctx, &obj))
        return false;

    switch (obj.type)
    {
        case MPACK_TYPE_POSITIVE_FIXNUM:
        case MPACK_TYPE_UINT8:
            *c = obj.as.u8;
            return true;
        default:
            ctx->error = INVALID_TYPE_ERROR;
            return false;
    }
}

bool mpack_read_ushort(mpack_ctx_t* ctx, uint16_t* s)
{
    mpack_object_t obj;

    if (!mpack_read_object(ctx, &obj))
        return false;

    switch (obj.type)
    {
        case MPACK_TYPE_POSITIVE_FIXNUM:
        case MPACK_TYPE_UINT8:
            *s = obj.as.u8;
            return true;
        case MPACK_TYPE_UINT16:
            *s = obj.as.u16;
            return true;
        default:
            ctx->error = INVALID_TYPE_ERROR;
            return false;
    }
}

bool mpack_read_uint(mpack_ctx_t* ctx, uint32_t* i)
{
    mpack_object_t obj;

    if (!mpack_read_object(ctx, &obj))
        return false;

    switch (obj.type)
    {
        case MPACK_TYPE_POSITIVE_FIXNUM:
        case MPACK_TYPE_UINT8:
            *i = obj.as.u8;
            return true;
        case MPACK_TYPE_UINT16:
            *i = obj.as.u16;
            return true;
        case MPACK_TYPE_UINT32:
            *i = obj.as.u32;
            return true;
        default:
            ctx->error = INVALID_TYPE_ERROR;
            return false;
    }
}

bool mpack_read_ulong(mpack_ctx_t* ctx, uint64_t* u)
{
    mpack_object_t obj;

    if (!mpack_read_object(ctx, &obj))
        return false;

    switch (obj.type)
    {
        case MPACK_TYPE_POSITIVE_FIXNUM:
        case MPACK_TYPE_UINT8:
            *u = obj.as.u8;
            return true;
        case MPACK_TYPE_UINT16:
            *u = obj.as.u16;
            return true;
        case MPACK_TYPE_UINT32:
            *u = obj.as.u32;
            return true;
        case MPACK_TYPE_UINT64:
            *u = obj.as.u64;
            return true;
        default:
            ctx->error = INVALID_TYPE_ERROR;
            return false;
    }
}

bool mpack_read_uinteger(mpack_ctx_t* ctx, uint64_t* d)
{
    return mpack_read_ulong(ctx, d);
}

bool mpack_read_float(mpack_ctx_t* ctx, float* f)
{
    mpack_object_t obj;

    if (!mpack_read_object(ctx, &obj))
        return false;

    if (obj.type != MPACK_TYPE_FLOAT)
    {
        ctx->error = INVALID_TYPE_ERROR;
        return false;
    }

    *f = obj.as.flt;

    return true;
}

bool mpack_read_double(mpack_ctx_t* ctx, double* d)
{
    mpack_object_t obj;

    if (!mpack_read_object(ctx, &obj))
        return false;

    if (obj.type != MPACK_TYPE_DOUBLE)
    {
        ctx->error = INVALID_TYPE_ERROR;
        return false;
    }

    *d = obj.as.dbl;

    return true;
}

bool mpack_read_decimal(mpack_ctx_t* ctx, double* d)
{
    mpack_object_t obj;

    if (!mpack_read_object(ctx, &obj))
        return false;

    switch (obj.type)
    {
        case MPACK_TYPE_FLOAT:
            *d = (double)obj.as.flt;
            return true;
        case MPACK_TYPE_DOUBLE:
            *d = obj.as.dbl;
            return true;
        default:
            ctx->error = INVALID_TYPE_ERROR;
            return false;
    }
}

bool mpack_read_nil(mpack_ctx_t* ctx)
{
    mpack_object_t obj;

    if (!mpack_read_object(ctx, &obj))
        return false;

    if (obj.type == MPACK_TYPE_NIL)
        return true;

    ctx->error = INVALID_TYPE_ERROR;
    return false;
}

bool mpack_read_bool(mpack_ctx_t* ctx, bool* b)
{
    mpack_object_t obj;

    if (!mpack_read_object(ctx, &obj))
        return false;

    if (obj.type != MPACK_TYPE_BOOLEAN)
    {
        ctx->error = INVALID_TYPE_ERROR;
        return false;
    }

    if (obj.as.boolean)
        *b = true;
    else
        *b = false;

    return true;
}

bool mpack_read_bool_as_u8(mpack_ctx_t* ctx, uint8_t* b)
{
    mpack_object_t obj;

    if (!mpack_read_object(ctx, &obj))
        return false;

    if (obj.type != MPACK_TYPE_BOOLEAN)
    {
        ctx->error = INVALID_TYPE_ERROR;
        return false;
    }

    if (obj.as.boolean)
        *b = 1;
    else
        *b = 0;

    return true;
}

bool mpack_read_str_size(mpack_ctx_t* ctx, uint32_t* size)
{
    mpack_object_t obj;

    if (!mpack_read_object(ctx, &obj))
        return false;

    switch (obj.type)
    {
        case MPACK_TYPE_FIXSTR:
        case MPACK_TYPE_STR8:
        case MPACK_TYPE_STR16:
        case MPACK_TYPE_STR32:
            *size = obj.as.str_size;
            return true;
        default:
            ctx->error = INVALID_TYPE_ERROR;
            return false;
    }
}

bool mpack_read_str(mpack_ctx_t* ctx, char* data, uint32_t* size)
{
    uint32_t str_size = 0;

    if (!mpack_read_str_size(ctx, &str_size))
        return false;

    if ((str_size + 1) > *size)
    {
        *size = str_size;
        ctx->error = STR_DATA_LENGTH_TOO_LONG_ERROR;
        return false;
    }

    if (!ctx->read(ctx, data, str_size))
    {
        ctx->error = DATA_READING_ERROR;
        return false;
    }

    data[str_size] = 0;

    *size = str_size;
    return true;
}

bool mpack_read_bin_size(mpack_ctx_t* ctx, uint32_t* size)
{
    mpack_object_t obj;

    if (!mpack_read_object(ctx, &obj))
        return false;

    switch (obj.type)
    {
        case MPACK_TYPE_BIN8:
        case MPACK_TYPE_BIN16:
        case MPACK_TYPE_BIN32:
            *size = obj.as.bin_size;
            return true;
        default:
            ctx->error = INVALID_TYPE_ERROR;
            return false;
    }
}

bool mpack_read_bin(mpack_ctx_t* ctx, void* data, uint32_t* size)
{
    uint32_t bin_size = 0;

    if (!mpack_read_bin_size(ctx, &bin_size))
        return false;

    if (bin_size > *size)
    {
        ctx->error = BIN_DATA_LENGTH_TOO_LONG_ERROR;
        return false;
    }

    if (!ctx->read(ctx, data, bin_size))
    {
        ctx->error = DATA_READING_ERROR;
        return false;
    }

    *size = bin_size;
    return true;
}

bool mpack_read_array(mpack_ctx_t* ctx, uint32_t* size)
{
    mpack_object_t obj;

    if (!mpack_read_object(ctx, &obj))
        return false;

    switch (obj.type)
    {
        case MPACK_TYPE_FIXARRAY:
        case MPACK_TYPE_ARRAY16:
        case MPACK_TYPE_ARRAY32:
            *size = obj.as.array_size;
            return true;
        default:
            ctx->error = INVALID_TYPE_ERROR;
            return false;
    }
}

bool mpack_read_map(mpack_ctx_t* ctx, uint32_t* size)
{
    mpack_object_t obj;

    if (!mpack_read_object(ctx, &obj))
        return false;

    switch (obj.type)
    {
        case MPACK_TYPE_FIXMAP:
        case MPACK_TYPE_MAP16:
        case MPACK_TYPE_MAP32:
            *size = obj.as.map_size;
            return true;
        default:
            ctx->error = INVALID_TYPE_ERROR;
            return false;
    }
}

bool mpack_read_fixext1_marker(mpack_ctx_t* ctx, int8_t* type)
{
    mpack_object_t obj;

    if (!mpack_read_object(ctx, &obj))
        return false;

    if (obj.type != MPACK_TYPE_FIXEXT1)
    {
        ctx->error = INVALID_TYPE_ERROR;
        return false;
    }

    *type = obj.as.ext.type;
    return true;
}

bool mpack_read_fixext1(mpack_ctx_t* ctx, int8_t* type, void* data)
{
    if (!mpack_read_fixext1_marker(ctx, type))
        return false;

    if (ctx->read(ctx, data, 1))
        return true;

    ctx->error = DATA_READING_ERROR;
    return false;
}

bool mpack_read_fixext2_marker(mpack_ctx_t* ctx, int8_t* type)
{
    mpack_object_t obj;

    if (!mpack_read_object(ctx, &obj))
        return false;

    if (obj.type != MPACK_TYPE_FIXEXT2)
    {
        ctx->error = INVALID_TYPE_ERROR;
        return false;
    }

    *type = obj.as.ext.type;
    return true;
}

bool mpack_read_fixext2(mpack_ctx_t* ctx, int8_t* type, void* data)
{
    if (!mpack_read_fixext2_marker(ctx, type))
        return false;

    if (ctx->read(ctx, data, 2))
        return true;

    ctx->error = DATA_READING_ERROR;
    return false;
}

bool mpack_read_fixext4_marker(mpack_ctx_t* ctx, int8_t* type)
{
    mpack_object_t obj;

    if (!mpack_read_object(ctx, &obj))
        return false;

    if (obj.type != MPACK_TYPE_FIXEXT4)
    {
        ctx->error = INVALID_TYPE_ERROR;
        return false;
    }

    *type = obj.as.ext.type;
    return true;
}

bool mpack_read_fixext4(mpack_ctx_t* ctx, int8_t* type, void* data)
{
    if (!mpack_read_fixext4_marker(ctx, type))
        return false;

    if (ctx->read(ctx, data, 4))
        return true;

    ctx->error = DATA_READING_ERROR;
    return false;
}

bool mpack_read_fixext8_marker(mpack_ctx_t* ctx, int8_t* type)
{
    mpack_object_t obj;

    if (!mpack_read_object(ctx, &obj))
        return false;

    if (obj.type != MPACK_TYPE_FIXEXT8)
    {
        ctx->error = INVALID_TYPE_ERROR;
        return false;
    }

    *type = obj.as.ext.type;
    return true;
}

bool mpack_read_fixext8(mpack_ctx_t* ctx, int8_t* type, void* data)
{
    if (!mpack_read_fixext8_marker(ctx, type))
        return false;

    if (ctx->read(ctx, data, 8))
        return true;

    ctx->error = DATA_READING_ERROR;
    return false;
}

bool mpack_read_fixext16_marker(mpack_ctx_t* ctx, int8_t* type)
{
    mpack_object_t obj;

    if (!mpack_read_object(ctx, &obj))
        return false;

    if (obj.type != MPACK_TYPE_FIXEXT16)
    {
        ctx->error = INVALID_TYPE_ERROR;
        return false;
    }

    *type = obj.as.ext.type;
    return true;
}

bool mpack_read_fixext16(mpack_ctx_t* ctx, int8_t* type, void* data)
{
    if (!mpack_read_fixext16_marker(ctx, type))
        return false;

    if (ctx->read(ctx, data, 16))
        return true;

    ctx->error = DATA_READING_ERROR;
    return false;
}

bool mpack_read_ext8_marker(mpack_ctx_t* ctx, int8_t* type, uint8_t* size)
{
    mpack_object_t obj;

    if (!mpack_read_object(ctx, &obj))
        return false;

    if (obj.type != MPACK_TYPE_EXT8)
    {
        ctx->error = INVALID_TYPE_ERROR;
        return false;
    }

    *type = obj.as.ext.type;
    *size = (uint8_t)obj.as.ext.size;

    return true;
}

bool mpack_read_ext8(mpack_ctx_t* ctx, int8_t* type, uint8_t* size, void* data)
{
    if (!mpack_read_ext8_marker(ctx, type, size))
        return false;

    if (ctx->read(ctx, data, *size))
        return true;

    ctx->error = DATA_READING_ERROR;
    return false;
}

bool mpack_read_ext16_marker(mpack_ctx_t* ctx, int8_t* type, uint16_t* size)
{
    mpack_object_t obj;

    if (!mpack_read_object(ctx, &obj))
        return false;

    if (obj.type != MPACK_TYPE_EXT16)
    {
        ctx->error = INVALID_TYPE_ERROR;
        return false;
    }

    *type = obj.as.ext.type;
    *size = (uint16_t)obj.as.ext.size;

    return true;
}

bool mpack_read_ext16(mpack_ctx_t* ctx, int8_t* type, uint16_t* size,
                      void* data)
{
    if (!mpack_read_ext16_marker(ctx, type, size))
        return false;

    if (ctx->read(ctx, data, *size))
        return true;

    ctx->error = DATA_READING_ERROR;
    return false;
}

bool mpack_read_ext32_marker(mpack_ctx_t* ctx, int8_t* type, uint32_t* size)
{
    mpack_object_t obj;

    if (!mpack_read_object(ctx, &obj))
        return false;

    if (obj.type != MPACK_TYPE_EXT32)
    {
        ctx->error = INVALID_TYPE_ERROR;
        return false;
    }

    *type = obj.as.ext.type;
    *size = obj.as.ext.size;

    return true;
}

bool mpack_read_ext32(mpack_ctx_t* ctx, int8_t* type, uint32_t* size,
                      void* data)
{
    if (!mpack_read_ext32_marker(ctx, type, size))
        return false;

    if (ctx->read(ctx, data, *size))
        return true;

    ctx->error = DATA_READING_ERROR;
    return false;
}

bool mpack_read_ext_marker(mpack_ctx_t* ctx, int8_t* type, uint32_t* size)
{
    mpack_object_t obj;

    if (!mpack_read_object(ctx, &obj))
        return false;

    switch (obj.type)
    {
        case MPACK_TYPE_FIXEXT1:
        case MPACK_TYPE_FIXEXT2:
        case MPACK_TYPE_FIXEXT4:
        case MPACK_TYPE_FIXEXT8:
        case MPACK_TYPE_FIXEXT16:
        case MPACK_TYPE_EXT8:
        case MPACK_TYPE_EXT16:
        case MPACK_TYPE_EXT32:
            *type = obj.as.ext.type;
            *size = obj.as.ext.size;
            return true;
        default:
            ctx->error = INVALID_TYPE_ERROR;
            return false;
    }
}

bool mpack_read_ext(mpack_ctx_t* ctx, int8_t* type, uint32_t* size, void* data)
{
    if (!mpack_read_ext_marker(ctx, type, size))
        return false;

    if (ctx->read(ctx, data, *size))
        return true;

    ctx->error = DATA_READING_ERROR;
    return false;
}

bool mpack_read_object(mpack_ctx_t* ctx, mpack_object_t* obj)
{
    uint8_t type_marker = 0;

    if (!read_type_marker(ctx, &type_marker))
        return false;

    if (type_marker <= 0x7F)
    {
        obj->type = MPACK_TYPE_POSITIVE_FIXNUM;
        obj->as.u8 = type_marker;
    }
    else if (type_marker <= 0x8F)
    {
        obj->type = MPACK_TYPE_FIXMAP;
        obj->as.map_size = type_marker & FIXMAP_SIZE;
    }
    else if (type_marker <= 0x9F)
    {
        obj->type = MPACK_TYPE_FIXARRAY;
        obj->as.array_size = type_marker & FIXARRAY_SIZE;
    }
    else if (type_marker <= 0xBF)
    {
        obj->type = MPACK_TYPE_FIXSTR;
        obj->as.str_size = type_marker & FIXSTR_SIZE;
    }
    else if (type_marker == NIL_MARKER)
    {
        obj->type = MPACK_TYPE_NIL;
        obj->as.u8 = 0;
    }
    else if (type_marker == FALSE_MARKER)
    {
        obj->type = MPACK_TYPE_BOOLEAN;
        obj->as.boolean = false;
    }
    else if (type_marker == TRUE_MARKER)
    {
        obj->type = MPACK_TYPE_BOOLEAN;
        obj->as.boolean = true;
    }
    else if (type_marker == BIN8_MARKER)
    {
        obj->type = MPACK_TYPE_BIN8;
        if (!ctx->read(ctx, &obj->as.u8, sizeof(uint8_t)))
        {
            ctx->error = LENGTH_READING_ERROR;
            return false;
        }
        obj->as.bin_size = obj->as.u8;
    }
    else if (type_marker == BIN16_MARKER)
    {
        obj->type = MPACK_TYPE_BIN16;
        if (!ctx->read(ctx, &obj->as.u16, sizeof(uint16_t)))
        {
            ctx->error = LENGTH_READING_ERROR;
            return false;
        }
        obj->as.bin_size = endian_ntohs(obj->as.u16);
    }
    else if (type_marker == BIN32_MARKER)
    {
        obj->type = MPACK_TYPE_BIN32;
        if (!ctx->read(ctx, &obj->as.u32, sizeof(uint32_t)))
        {
            ctx->error = LENGTH_READING_ERROR;
            return false;
        }
        obj->as.bin_size = endian_ntohl(obj->as.u32);
    }
    else if (type_marker == EXT8_MARKER)
    {
        uint8_t ext_size;
        int8_t ext_type;

        obj->type = MPACK_TYPE_EXT8;
        if (!ctx->read(ctx, &ext_size, sizeof(uint8_t)))
        {
            ctx->error = LENGTH_READING_ERROR;
            return false;
        }
        if (!ctx->read(ctx, &ext_type, sizeof(int8_t)))
        {
            ctx->error = EXT_TYPE_READING_ERROR;
            return false;
        }
        obj->as.ext.size = ext_size;
        obj->as.ext.type = ext_type;
    }
    else if (type_marker == EXT16_MARKER)
    {
        int8_t ext_type;
        uint16_t ext_size;

        obj->type = MPACK_TYPE_EXT16;
        if (!ctx->read(ctx, &ext_size, sizeof(uint16_t)))
        {
            ctx->error = LENGTH_READING_ERROR;
            return false;
        }
        if (!ctx->read(ctx, &ext_type, sizeof(int8_t)))
        {
            ctx->error = EXT_TYPE_READING_ERROR;
            return false;
        }
        obj->as.ext.size = endian_ntohs(ext_size);
        obj->as.ext.type = ext_type;
    }
    else if (type_marker == EXT32_MARKER)
    {
        int8_t ext_type;
        uint32_t ext_size;

        obj->type = MPACK_TYPE_EXT32;
        if (!ctx->read(ctx, &ext_size, sizeof(uint32_t)))
        {
            ctx->error = LENGTH_READING_ERROR;
            return false;
        }
        if (!ctx->read(ctx, &ext_type, sizeof(int8_t)))
        {
            ctx->error = EXT_TYPE_READING_ERROR;
            return false;
        }
        obj->as.ext.size = endian_ntohl(ext_size);
        obj->as.ext.type = ext_type;
    }
    else if (type_marker == FLOAT_MARKER)
    {
        obj->type = MPACK_TYPE_FLOAT;
        if (!ctx->read(ctx, &obj->as.flt, sizeof(float)))
        {
            ctx->error = DATA_READING_ERROR;
            return false;
        }
        obj->as.flt = endian_ntohl(obj->as.flt);
    }
    else if (type_marker == DOUBLE_MARKER)
    {
        obj->type = MPACK_TYPE_DOUBLE;
        if (!ctx->read(ctx, &obj->as.dbl, sizeof(double)))
        {
            ctx->error = DATA_READING_ERROR;
            return false;
        }
        obj->as.dbl = endian_ntohll(obj->as.dbl);
    }
    else if (type_marker == U8_MARKER)
    {
        obj->type = MPACK_TYPE_UINT8;
        if (!ctx->read(ctx, &obj->as.u8, sizeof(uint8_t)))
        {
            ctx->error = DATA_READING_ERROR;
            return false;
        }
    }
    else if (type_marker == U16_MARKER)
    {
        obj->type = MPACK_TYPE_UINT16;
        if (!ctx->read(ctx, &obj->as.u16, sizeof(uint16_t)))
        {
            ctx->error = DATA_READING_ERROR;
            return false;
        }
        obj->as.u16 = endian_ntohs(obj->as.u16);
    }
    else if (type_marker == U32_MARKER)
    {
        obj->type = MPACK_TYPE_UINT32;
        if (!ctx->read(ctx, &obj->as.u32, sizeof(uint32_t)))
        {
            ctx->error = DATA_READING_ERROR;
            return false;
        }
        obj->as.u32 = endian_ntohl(obj->as.u32);
    }
    else if (type_marker == U64_MARKER)
    {
        obj->type = MPACK_TYPE_UINT64;
        if (!ctx->read(ctx, &obj->as.u64, sizeof(uint64_t)))
        {
            ctx->error = DATA_READING_ERROR;
            return false;
        }
        obj->as.u64 = endian_ntohll(obj->as.u64);
    }
    else if (type_marker == S8_MARKER)
    {
        obj->type = MPACK_TYPE_SINT8;
        if (!ctx->read(ctx, &obj->as.s8, sizeof(int8_t)))
        {
            ctx->error = DATA_READING_ERROR;
            return false;
        }
    }
    else if (type_marker == S16_MARKER)
    {
        obj->type = MPACK_TYPE_SINT16;
        if (!ctx->read(ctx, &obj->as.s16, sizeof(int16_t)))
        {
            ctx->error = DATA_READING_ERROR;
            return false;
        }
        obj->as.s16 = endian_ntohs(obj->as.s16);
    }
    else if (type_marker == S32_MARKER)
    {
        obj->type = MPACK_TYPE_SINT32;
        if (!ctx->read(ctx, &obj->as.s32, sizeof(int32_t)))
        {
            ctx->error = DATA_READING_ERROR;
            return false;
        }
        obj->as.s32 = endian_ntohl(obj->as.s32);
    }
    else if (type_marker == S64_MARKER)
    {
        obj->type = MPACK_TYPE_SINT64;
        if (!ctx->read(ctx, &obj->as.s64, sizeof(int64_t)))
        {
            ctx->error = DATA_READING_ERROR;
            return false;
        }
        obj->as.s64 = endian_ntohll(obj->as.s64);
    }
    else if (type_marker == FIXEXT1_MARKER)
    {
        obj->type = MPACK_TYPE_FIXEXT1;
        if (!ctx->read(ctx, &obj->as.ext.type, sizeof(int8_t)))
        {
            ctx->error = EXT_TYPE_READING_ERROR;
            return false;
        }
        obj->as.ext.size = 1;
    }
    else if (type_marker == FIXEXT2_MARKER)
    {
        obj->type = MPACK_TYPE_FIXEXT2;
        if (!ctx->read(ctx, &obj->as.ext.type, sizeof(int8_t)))
        {
            ctx->error = EXT_TYPE_READING_ERROR;
            return false;
        }
        obj->as.ext.size = 2;
    }
    else if (type_marker == FIXEXT4_MARKER)
    {
        obj->type = MPACK_TYPE_FIXEXT4;
        if (!ctx->read(ctx, &obj->as.ext.type, sizeof(int8_t)))
        {
            ctx->error = EXT_TYPE_READING_ERROR;
            return false;
        }
        obj->as.ext.size = 4;
    }
    else if (type_marker == FIXEXT8_MARKER)
    {
        obj->type = MPACK_TYPE_FIXEXT8;
        if (!ctx->read(ctx, &obj->as.ext.type, sizeof(int8_t)))
        {
            ctx->error = EXT_TYPE_READING_ERROR;
            return false;
        }
        obj->as.ext.size = 8;
    }
    else if (type_marker == FIXEXT16_MARKER)
    {
        obj->type = MPACK_TYPE_FIXEXT16;
        if (!ctx->read(ctx, &obj->as.ext.type, sizeof(int8_t)))
        {
            ctx->error = EXT_TYPE_READING_ERROR;
            return false;
        }
        obj->as.ext.size = 16;
    }
    else if (type_marker == STR8_MARKER)
    {
        obj->type = MPACK_TYPE_STR8;
        if (!ctx->read(ctx, &obj->as.u8, sizeof(uint8_t)))
        {
            ctx->error = DATA_READING_ERROR;
            return false;
        }
        obj->as.str_size = obj->as.u8;
    }
    else if (type_marker == STR16_MARKER)
    {
        obj->type = MPACK_TYPE_STR16;
        if (!ctx->read(ctx, &obj->as.u16, sizeof(uint16_t)))
        {
            ctx->error = DATA_READING_ERROR;
            return false;
        }
        obj->as.str_size = endian_ntohs(obj->as.u16);
    }
    else if (type_marker == STR32_MARKER)
    {
        obj->type = MPACK_TYPE_STR32;
        if (!ctx->read(ctx, &obj->as.u32, sizeof(uint32_t)))
        {
            ctx->error = DATA_READING_ERROR;
            return false;
        }
        obj->as.str_size = endian_ntohl(obj->as.u32);
    }
    else if (type_marker == ARRAY16_MARKER)
    {
        obj->type = MPACK_TYPE_ARRAY16;
        if (!ctx->read(ctx, &obj->as.u16, sizeof(uint16_t)))
        {
            ctx->error = DATA_READING_ERROR;
            return false;
        }
        obj->as.array_size = endian_ntohs(obj->as.u16);
    }
    else if (type_marker == ARRAY32_MARKER)
    {
        obj->type = MPACK_TYPE_ARRAY32;
        if (!ctx->read(ctx, &obj->as.u32, sizeof(uint32_t)))
        {
            ctx->error = DATA_READING_ERROR;
            return false;
        }
        obj->as.array_size = endian_ntohl(obj->as.u32);
    }
    else if (type_marker == MAP16_MARKER)
    {
        obj->type = MPACK_TYPE_MAP16;
        if (!ctx->read(ctx, &obj->as.u16, sizeof(uint16_t)))
        {
            ctx->error = DATA_READING_ERROR;
            return false;
        }
        obj->as.map_size = endian_ntohs(obj->as.u16);
    }
    else if (type_marker == MAP32_MARKER)
    {
        obj->type = MPACK_TYPE_MAP32;
        if (!ctx->read(ctx, &obj->as.u32, sizeof(uint32_t)))
        {
            ctx->error = DATA_READING_ERROR;
            return false;
        }
        obj->as.map_size = endian_ntohl(obj->as.u32);
    }
    else if (type_marker >= NEGATIVE_FIXNUM_MARKER)
    {
        obj->type = MPACK_TYPE_NEGATIVE_FIXNUM;
        obj->as.s8 = type_marker;
    }
    else
    {
        ctx->error = INVALID_TYPE_ERROR;
        return false;
    }

    return true;
}

bool mpack_object_is_char(mpack_object_t* obj)
{
    switch (obj->type)
    {
        case MPACK_TYPE_NEGATIVE_FIXNUM:
        case MPACK_TYPE_SINT8:
            return true;
        default:
            return false;
    }
}

bool mpack_object_is_short(mpack_object_t* obj)
{
    switch (obj->type)
    {
        case MPACK_TYPE_NEGATIVE_FIXNUM:
        case MPACK_TYPE_SINT8:
        case MPACK_TYPE_SINT16:
            return true;
        default:
            return false;
    }
}

bool mpack_object_is_int(mpack_object_t* obj)
{
    switch (obj->type)
    {
        case MPACK_TYPE_NEGATIVE_FIXNUM:
        case MPACK_TYPE_SINT8:
        case MPACK_TYPE_SINT16:
        case MPACK_TYPE_SINT32:
            return true;
        default:
            return false;
    }
}

bool mpack_object_is_long(mpack_object_t* obj)
{
    switch (obj->type)
    {
        case MPACK_TYPE_NEGATIVE_FIXNUM:
        case MPACK_TYPE_SINT8:
        case MPACK_TYPE_SINT16:
        case MPACK_TYPE_SINT32:
        case MPACK_TYPE_SINT64:
            return true;
        default:
            return false;
    }
}

bool mpack_object_is_sinteger(mpack_object_t* obj)
{
    return mpack_object_is_long(obj);
}

bool mpack_object_is_uchar(mpack_object_t* obj)
{
    switch (obj->type)
    {
        case MPACK_TYPE_POSITIVE_FIXNUM:
        case MPACK_TYPE_UINT8:
            return true;
        default:
            return false;
    }
}

bool mpack_object_is_ushort(mpack_object_t* obj)
{
    switch (obj->type)
    {
        case MPACK_TYPE_POSITIVE_FIXNUM:
        case MPACK_TYPE_UINT8:
            return true;
        case MPACK_TYPE_UINT16:
            return true;
        default:
            return false;
    }
}

bool mpack_object_is_uint(mpack_object_t* obj)
{
    switch (obj->type)
    {
        case MPACK_TYPE_POSITIVE_FIXNUM:
        case MPACK_TYPE_UINT8:
        case MPACK_TYPE_UINT16:
        case MPACK_TYPE_UINT32:
            return true;
        default:
            return false;
    }
}

bool mpack_object_is_ulong(mpack_object_t* obj)
{
    switch (obj->type)
    {
        case MPACK_TYPE_POSITIVE_FIXNUM:
        case MPACK_TYPE_UINT8:
        case MPACK_TYPE_UINT16:
        case MPACK_TYPE_UINT32:
        case MPACK_TYPE_UINT64:
            return true;
        default:
            return false;
    }
}

bool mpack_object_is_uinteger(mpack_object_t* obj)
{
    return mpack_object_is_ulong(obj);
}

bool mpack_object_is_float(mpack_object_t* obj)
{
    if (obj->type == MPACK_TYPE_FLOAT)
        return true;

    return false;
}

bool mpack_object_is_double(mpack_object_t* obj)
{
    if (obj->type == MPACK_TYPE_DOUBLE)
        return true;

    return false;
}

bool mpack_object_is_nil(mpack_object_t* obj)
{
    if (obj->type == MPACK_TYPE_NIL)
        return true;

    return false;
}

bool mpack_object_is_bool(mpack_object_t* obj)
{
    if (obj->type == MPACK_TYPE_BOOLEAN)
        return true;

    return false;
}

bool mpack_object_is_str(mpack_object_t* obj)
{
    switch (obj->type)
    {
        case MPACK_TYPE_FIXSTR:
        case MPACK_TYPE_STR8:
        case MPACK_TYPE_STR16:
        case MPACK_TYPE_STR32:
            return true;
        default:
            return false;
    }
}

bool mpack_object_is_bin(mpack_object_t* obj)
{
    switch (obj->type)
    {
        case MPACK_TYPE_BIN8:
        case MPACK_TYPE_BIN16:
        case MPACK_TYPE_BIN32:
            return true;
        default:
            return false;
    }
}

bool mpack_object_is_array(mpack_object_t* obj)
{
    switch (obj->type)
    {
        case MPACK_TYPE_FIXARRAY:
        case MPACK_TYPE_ARRAY16:
        case MPACK_TYPE_ARRAY32:
            return true;
        default:
            return false;
    }
}

bool mpack_object_is_map(mpack_object_t* obj)
{
    switch (obj->type)
    {
        case MPACK_TYPE_FIXMAP:
        case MPACK_TYPE_MAP16:
        case MPACK_TYPE_MAP32:
            return true;
        default:
            return false;
    }
}

bool mpack_object_is_ext(mpack_object_t* obj)
{
    switch (obj->type)
    {
        case MPACK_TYPE_FIXEXT1:
        case MPACK_TYPE_FIXEXT2:
        case MPACK_TYPE_FIXEXT4:
        case MPACK_TYPE_FIXEXT8:
        case MPACK_TYPE_FIXEXT16:
        case MPACK_TYPE_EXT8:
        case MPACK_TYPE_EXT16:
        case MPACK_TYPE_EXT32:
            return true;
        default:
            return false;
    }
}

bool mpack_object_as_char(mpack_object_t* obj, int8_t* c)
{
    switch (obj->type)
    {
        case MPACK_TYPE_POSITIVE_FIXNUM:
        case MPACK_TYPE_NEGATIVE_FIXNUM:
        case MPACK_TYPE_SINT8:
            *c = obj->as.s8;
            return true;
        case MPACK_TYPE_UINT8:
            if (obj->as.u8 <= 127)
            {
                *c = obj->as.s8;
                return true;
            }
        default:
            return false;
    }
}

bool mpack_object_as_short(mpack_object_t* obj, int16_t* s)
{
    switch (obj->type)
    {
        case MPACK_TYPE_POSITIVE_FIXNUM:
        case MPACK_TYPE_NEGATIVE_FIXNUM:
        case MPACK_TYPE_SINT8:
            *s = obj->as.s8;
            return true;
        case MPACK_TYPE_UINT8:
            *s = obj->as.u8;
            return true;
        case MPACK_TYPE_SINT16:
            *s = obj->as.s16;
            return true;
        case MPACK_TYPE_UINT16:
            if (obj->as.u16 <= 32767)
            {
                *s = obj->as.u16;
                return true;
            }
        default:
            return false;
    }
}

bool mpack_object_as_int(mpack_object_t* obj, int32_t* i)
{
    switch (obj->type)
    {
        case MPACK_TYPE_POSITIVE_FIXNUM:
        case MPACK_TYPE_NEGATIVE_FIXNUM:
        case MPACK_TYPE_SINT8:
            *i = obj->as.s8;
            return true;
        case MPACK_TYPE_UINT8:
            *i = obj->as.u8;
            return true;
        case MPACK_TYPE_SINT16:
            *i = obj->as.s16;
            return true;
        case MPACK_TYPE_UINT16:
            *i = obj->as.u16;
            return true;
        case MPACK_TYPE_SINT32:
            *i = obj->as.s32;
            return true;
        case MPACK_TYPE_UINT32:
            if (obj->as.u32 <= 2147483647)
            {
                *i = obj->as.u32;
                return true;
            }
        default:
            return false;
    }
}

bool mpack_object_as_long(mpack_object_t* obj, int64_t* d)
{
    switch (obj->type)
    {
        case MPACK_TYPE_POSITIVE_FIXNUM:
        case MPACK_TYPE_NEGATIVE_FIXNUM:
        case MPACK_TYPE_SINT8:
            *d = obj->as.s8;
            return true;
        case MPACK_TYPE_UINT8:
            *d = obj->as.u8;
            return true;
        case MPACK_TYPE_SINT16:
            *d = obj->as.s16;
            return true;
        case MPACK_TYPE_UINT16:
            *d = obj->as.u16;
            return true;
        case MPACK_TYPE_SINT32:
            *d = obj->as.s32;
            return true;
        case MPACK_TYPE_UINT32:
            *d = obj->as.u32;
            return true;
        case MPACK_TYPE_SINT64:
            *d = obj->as.s64;
            return true;
        case MPACK_TYPE_UINT64:
            if (obj->as.u64 <= 9223372036854775807llu)
            {
                *d = obj->as.u64;
                return true;
            }
        default:
            return false;
    }
}

bool mpack_object_as_sinteger(mpack_object_t* obj, int64_t* d)
{
    return mpack_object_as_long(obj, d);
}

bool mpack_object_as_uchar(mpack_object_t* obj, uint8_t* c)
{
    switch (obj->type)
    {
        case MPACK_TYPE_POSITIVE_FIXNUM:
        case MPACK_TYPE_UINT8:
            *c = obj->as.u8;
            return true;
        default:
            return false;
    }
}

bool mpack_object_as_ushort(mpack_object_t* obj, uint16_t* s)
{
    switch (obj->type)
    {
        case MPACK_TYPE_POSITIVE_FIXNUM:
        case MPACK_TYPE_UINT8:
            *s = obj->as.u8;
            return true;
        case MPACK_TYPE_UINT16:
            *s = obj->as.u16;
            return true;
        default:
            return false;
    }
}

bool mpack_object_as_uint(mpack_object_t* obj, uint32_t* i)
{
    switch (obj->type)
    {
        case MPACK_TYPE_POSITIVE_FIXNUM:
        case MPACK_TYPE_UINT8:
            *i = obj->as.u8;
            return true;
        case MPACK_TYPE_UINT16:
            *i = obj->as.u16;
            return true;
        case MPACK_TYPE_UINT32:
            *i = obj->as.u32;
            return true;
        default:
            return false;
    }
}

bool mpack_object_as_ulong(mpack_object_t* obj, uint64_t* u)
{
    switch (obj->type)
    {
        case MPACK_TYPE_POSITIVE_FIXNUM:
        case MPACK_TYPE_UINT8:
            *u = obj->as.u8;
            return true;
        case MPACK_TYPE_UINT16:
            *u = obj->as.u16;
            return true;
        case MPACK_TYPE_UINT32:
            *u = obj->as.u32;
            return true;
        case MPACK_TYPE_UINT64:
            *u = obj->as.u64;
            return true;
        default:
            return false;
    }
}

bool mpack_object_as_uinteger(mpack_object_t* obj, uint64_t* d)
{
    return mpack_object_as_ulong(obj, d);
}

bool mpack_object_as_float(mpack_object_t* obj, float* f)
{
    if (obj->type == MPACK_TYPE_FLOAT)
    {
        *f = obj->as.flt;
        return true;
    }

    return false;
}

bool mpack_object_as_double(mpack_object_t* obj, double* d)
{
    if (obj->type == MPACK_TYPE_DOUBLE)
    {
        *d = obj->as.dbl;
        return true;
    }

    return false;
}

bool mpack_object_as_bool(mpack_object_t* obj, bool* b)
{
    if (obj->type == MPACK_TYPE_BOOLEAN)
    {
        if (obj->as.boolean)
            *b = true;
        else
            *b = false;

        return true;
    }

    return false;
}

bool mpack_object_as_str(mpack_object_t* obj, uint32_t* size)
{
    switch (obj->type)
    {
        case MPACK_TYPE_FIXSTR:
        case MPACK_TYPE_STR8:
        case MPACK_TYPE_STR16:
        case MPACK_TYPE_STR32:
            *size = obj->as.str_size;
            return true;
        default:
            return false;
    }
}

bool mpack_object_as_bin(mpack_object_t* obj, uint32_t* size)
{
    switch (obj->type)
    {
        case MPACK_TYPE_BIN8:
        case MPACK_TYPE_BIN16:
        case MPACK_TYPE_BIN32:
            *size = obj->as.bin_size;
            return true;
        default:
            return false;
    }
}

bool mpack_object_as_array(mpack_object_t* obj, uint32_t* size)
{
    switch (obj->type)
    {
        case MPACK_TYPE_FIXARRAY:
        case MPACK_TYPE_ARRAY16:
        case MPACK_TYPE_ARRAY32:
            *size = obj->as.array_size;
            return true;
        default:
            return false;
    }
}

bool mpack_object_as_map(mpack_object_t* obj, uint32_t* size)
{
    switch (obj->type)
    {
        case MPACK_TYPE_FIXMAP:
        case MPACK_TYPE_MAP16:
        case MPACK_TYPE_MAP32:
            *size = obj->as.map_size;
            return true;
        default:
            return false;
    }
}

bool mpack_object_as_ext(mpack_object_t* obj, int8_t* type, uint32_t* size)
{
    switch (obj->type)
    {
        case MPACK_TYPE_FIXEXT1:
        case MPACK_TYPE_FIXEXT2:
        case MPACK_TYPE_FIXEXT4:
        case MPACK_TYPE_FIXEXT8:
        case MPACK_TYPE_FIXEXT16:
        case MPACK_TYPE_EXT8:
        case MPACK_TYPE_EXT16:
        case MPACK_TYPE_EXT32:
            *type = obj->as.ext.type;
            *size = obj->as.ext.size;
            return true;
        default:
            return false;
    }
}

bool mpack_object_to_str(mpack_ctx_t* ctx, mpack_object_t* obj, char* data,
                         uint32_t buf_size)
{
    uint32_t str_size = 0;
    switch (obj->type)
    {
        case MPACK_TYPE_FIXSTR:
        case MPACK_TYPE_STR8:
        case MPACK_TYPE_STR16:
        case MPACK_TYPE_STR32:
            str_size = obj->as.str_size;
            if ((str_size + 1) > buf_size)
            {
                ctx->error = STR_DATA_LENGTH_TOO_LONG_ERROR;
                return false;
            }

            if (!ctx->read(ctx, data, str_size))
            {
                ctx->error = DATA_READING_ERROR;
                return false;
            }

            data[str_size] = 0;
            return true;
        default:
            return false;
    }
}

bool mpack_object_to_bin(mpack_ctx_t* ctx, mpack_object_t* obj, void* data,
                         uint32_t buf_size)
{
    uint32_t bin_size = 0;
    switch (obj->type)
    {
        case MPACK_TYPE_BIN8:
        case MPACK_TYPE_BIN16:
        case MPACK_TYPE_BIN32:
            bin_size = obj->as.bin_size;
            if (bin_size > buf_size)
            {
                ctx->error = BIN_DATA_LENGTH_TOO_LONG_ERROR;
                return false;
            }

            if (!ctx->read(ctx, data, bin_size))
            {
                ctx->error = DATA_READING_ERROR;
                return false;
            }
            return true;
        default:
            return false;
    }
}

static void mpack_object_indent(stream_t* output, int depth)
{
    int i;

    for (i = 0; i < depth; i++)
    {
        stream_printf(output, "  ");
    }
}

static void mpack_object_suffix(stream_t* output, int formated, int iskey,
                                int islast)
{
    if (iskey)
    {
        stream_printf(output, ":");
    }
    else
    {
        if (!islast)
            stream_printf(output, ",");
        if (formated)
            stream_printf(output, "\n");
    }
}

static void mpack_ctx_dump_internal(stream_t* output, mpack_ctx_t* ctx,
                                    int formated, int depth, int iskey,
                                    int islast)
{
    int i;
    mpack_object_t obj;

    if (!mpack_read_object(ctx, &obj))
    {
        return;
    }

    switch (obj.type)
    {
        case MPACK_TYPE_FIXMAP:
        case MPACK_TYPE_MAP16:
        case MPACK_TYPE_MAP32:
            if (formated)
                mpack_object_indent(output, depth);
            stream_printf(output, "{");
            if (formated)
                stream_printf(output, "\n");
            for (i = 0; i < obj.as.map_size; i++)
            {
                mpack_ctx_dump_internal(output, ctx, formated, depth + 1, 1, 0);
                mpack_ctx_dump_internal(output, ctx, formated, depth + 1, 0,
                                        i == obj.as.map_size - 1);
            }
            if (formated)
                mpack_object_indent(output, depth);
            stream_printf(output, "}");
            mpack_object_suffix(output, formated, iskey, islast);
            break;
        case MPACK_TYPE_FIXARRAY:
        case MPACK_TYPE_ARRAY16:
        case MPACK_TYPE_ARRAY32:
            if (formated)
                mpack_object_indent(output, depth);
            stream_printf(output, "[");
            if (formated)
                stream_printf(output, "\n");

            for (i = 0; i < obj.as.array_size; i++)
            {
                mpack_ctx_dump_internal(output, ctx, formated, depth + 1, 0,
                                        i == obj.as.array_size - 1);
            }
            if (formated)
                mpack_object_indent(output, depth);
            stream_printf(output, "]");
            mpack_object_suffix(output, formated, iskey, islast);
            break;
        case MPACK_TYPE_FIXSTR:
        case MPACK_TYPE_STR8:
        case MPACK_TYPE_STR16:
        case MPACK_TYPE_STR32:
        {
            unsigned char* data = malloc(obj.as.str_size + 1);
            if (data == NULL)
            {
                fprintf(stderr, "alloc %d string failed.\n", obj.as.str_size);
                return;
            }

            if (!ctx->read(ctx, data, obj.as.str_size))
            {
                fprintf(stderr, "read %d string failed.\n", obj.as.str_size);
                return;
            }

            data[obj.as.str_size] = 0;

            if (formated && iskey)
                mpack_object_indent(output, depth);
            stream_printf(output, "\"");
            for (i = 0; i < obj.as.str_size; i++)
            {
                if (isprint(data[i]))
                {
                    if (data[i] == '"' || data[i] == '\\')
                    {
                        stream_printf(output, "\\x%hhx", data[i]);
                    }
                    else
                    {
                        stream_printf(output, "%c", data[i]);
                    }
                }
                else
                {
                    if (data[i] <= 0x7F)
                    {
                        stream_printf(output, "\\x%hhx", data[i]);
                    }
                    else
                    {
                        stream_printf(output, "%c", data[i]);
                    }
                }
            }
            stream_printf(output, "\"");
            mpack_object_suffix(output, formated, iskey, islast);
            free(data);
        }
        break;
        case MPACK_TYPE_BIN8:
        case MPACK_TYPE_BIN16:
        case MPACK_TYPE_BIN32:
        {
            char* data = malloc(obj.as.bin_size + 1);
            if (data == NULL)
            {
                fprintf(stderr, "alloc %d binary failed.\n", obj.as.bin_size);
                return;
            }

            if (!ctx->read(ctx, data, obj.as.bin_size))
            {
                fprintf(stderr, "read %d binary failed.\n", obj.as.bin_size);
                return;
            }

            if (formated && iskey)
                mpack_object_indent(output, depth);
            stream_printf(output, "\"|");
            for (i = 0; i < obj.as.bin_size; i++)
            {
                stream_printf(output, "\\x%hhx", data[i]);
            }
            stream_printf(output, "|\"");
            mpack_object_suffix(output, formated, iskey, islast);
            free(data);
        }
        break;
        case MPACK_TYPE_NIL:
            if (formated && iskey)
                mpack_object_indent(output, depth);
            stream_printf(output, "nil");
            mpack_object_suffix(output, formated, iskey, islast);
            break;
        case MPACK_TYPE_BOOLEAN:
            if (formated && iskey)
                mpack_object_indent(output, depth);
            if (obj.as.boolean)
            {
                stream_printf(output, "true");
            }
            else
            {
                stream_printf(output, "false");
            }
            mpack_object_suffix(output, formated, iskey, islast);
            break;
        case MPACK_TYPE_EXT8:
        case MPACK_TYPE_EXT16:
        case MPACK_TYPE_EXT32:
        case MPACK_TYPE_FIXEXT1:
        case MPACK_TYPE_FIXEXT2:
        case MPACK_TYPE_FIXEXT4:
        case MPACK_TYPE_FIXEXT8:
        case MPACK_TYPE_FIXEXT16:
        {
            char* data = malloc(obj.as.ext.size + 1);
            if (data == NULL)
            {
                fprintf(stderr, "alloc %d extension failed.\n",
                        obj.as.ext.size);
                return;
            }

            if (!ctx->read(ctx, data, obj.as.ext.size))
            {
                fprintf(stderr, "read %d externsion failed.\n",
                        obj.as.ext.size);
                return;
            }

            if (formated && iskey)
                mpack_object_indent(output, depth);
            stream_printf(output, "\"$%d$", obj.as.ext.type);
            for (i = 0; i < obj.as.ext.size; i++)
            {
                stream_printf(output, "\\x%hhx", data[i]);
            }
            stream_printf(output, "$\"");
            mpack_object_suffix(output, formated, iskey, islast);
            free(data);
        }
        break;
        case MPACK_TYPE_FLOAT:
            if (formated && iskey)
                mpack_object_indent(output, depth);
            stream_printf(output, "%f", obj.as.flt);
            mpack_object_suffix(output, formated, iskey, islast);
            break;
        case MPACK_TYPE_DOUBLE:
            if (formated && iskey)
                mpack_object_indent(output, depth);
            stream_printf(output, "%lf", obj.as.dbl);
            mpack_object_suffix(output, formated, iskey, islast);
            break;
        case MPACK_TYPE_POSITIVE_FIXNUM:
        case MPACK_TYPE_UINT8:
            if (formated && iskey)
                mpack_object_indent(output, depth);
            stream_printf(output, formated ? "0x%hhX" : "%u", obj.as.u8);
            mpack_object_suffix(output, formated, iskey, islast);
            break;
        case MPACK_TYPE_UINT16:
            if (formated && iskey)
                mpack_object_indent(output, depth);
            stream_printf(output, formated ? "0x%04X" : "%u", obj.as.u16);
            mpack_object_suffix(output, formated, iskey, islast);
            break;
        case MPACK_TYPE_UINT32:
            if (formated && iskey)
                mpack_object_indent(output, depth);
            stream_printf(output, formated ? "0x%08X" : "%u", obj.as.u32);
            mpack_object_suffix(output, formated, iskey, islast);
            break;
        case MPACK_TYPE_UINT64:
            if (formated && iskey)
                mpack_object_indent(output, depth);
            stream_printf(output, formated ? "0x%" PRIX64 : "%" PRIu64,
                          obj.as.u64);
            mpack_object_suffix(output, formated, iskey, islast);
            break;
        case MPACK_TYPE_NEGATIVE_FIXNUM:
        case MPACK_TYPE_SINT8:
            if (formated && iskey)
                mpack_object_indent(output, depth);
            stream_printf(output, "%d", obj.as.s8);
            mpack_object_suffix(output, formated, iskey, islast);
            break;
        case MPACK_TYPE_SINT16:
            if (formated && iskey)
                mpack_object_indent(output, depth);
            stream_printf(output, "%d", obj.as.s16);
            mpack_object_suffix(output, formated, iskey, islast);
            break;
        case MPACK_TYPE_SINT32:
            if (formated && iskey)
                mpack_object_indent(output, depth);
            stream_printf(output, "%d", obj.as.s32);
            mpack_object_suffix(output, formated, iskey, islast);
            break;
        case MPACK_TYPE_SINT64:
            if (formated && iskey)
                mpack_object_indent(output, depth);
            stream_printf(output, "%" PRId64, obj.as.s64);
            mpack_object_suffix(output, formated, iskey, islast);
            break;
        default:
            fprintf(stderr, "Unrecognized object type %u\n", obj.type);
            return;
    }
}

void mpack_ctx_dump(stream_t* output, mpack_ctx_t* ctx, int formated)
{
    stream_t* dumpoutput = NULL;

    if (output == NULL)
    {
        dumpoutput = stream_fopen(NULL, "w");
    }
    else
    {
        dumpoutput = output;
    }

    mpack_ctx_dump_internal(dumpoutput, ctx, formated, 0, 0, 1);
    if (!formated)
        stream_printf(dumpoutput, "\n");

    if (output == NULL)
    {
        stream_flush(dumpoutput);
    }
}

bool mpack_read_range(mpack_ctx_t* ctx, var_range_t* range)
{
    uint32_t size = 0;
    mpack_read_array(ctx, &size);
    if (size != 2)
    {
        return false;
    }

    mpack_read_s32(ctx, &range->start);
    mpack_read_s32(ctx, &range->end);
    return true;
}

bool mpack_write_range(mpack_ctx_t* ctx, var_range_t* range)
{
    mpack_write_array(ctx, 2);
    mpack_write_s32(ctx, range->start);
    mpack_write_s32(ctx, range->end);
    return true;
}

bool mpack_read_multi_range(mpack_ctx_t* ctx, var_multi_range_t* mrange)
{
    int i;
    uint32_t size = 0;
    mpack_read_array(ctx, &size);
    if (size >= MULTI_VALUE_MAX)
    {
        return false;
    }

    mrange->n = size;
    for (i = 0; i < mrange->n; i++)
    {
        if (!mpack_read_range(ctx, mrange->v + i))
        {
            return false;
        }
    }

    return true;
}

bool mpack_write_multi_range(mpack_ctx_t* ctx, var_multi_range_t* mrange)
{
    int i;

    mpack_write_array(ctx, mrange->n);
    for (i = 0; i < mrange->n; i++)
    {
        mpack_write_range(ctx, mrange->v + i);
    }

    return true;
}
