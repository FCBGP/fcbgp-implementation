#include <time.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "libstream.h"
#include "libmsgpack.h"

static bool stream_read_and_check(void *data, size_t size, stream_t * stream)
{
    return (stream_read(stream, data, size) == size);
}

static bool stream_reader(mpack_ctx_t * ctx, void *data, size_t size)
{
    return stream_read_and_check(data, size, (stream_t *) ctx->buf);
}

static size_t stream_writer(mpack_ctx_t * ctx, const void *data, size_t count)
{
    return stream_write((stream_t *) ctx->buf, (char *)data, count);
}

void mpack_write_cstr(mpack_ctx_t *mpctx, char *str)
{
    int len = strlen(str);

    mpack_write_str(mpctx, str, len);
    return;
}

void mpack_write_diskinfo(mpack_ctx_t *mpctx, uint8_t diskid, int n_luns, int n_nics)
{
    int i;

    mpack_write_map(mpctx, 6);
    mpack_write_cstr(mpctx, "diskid");
    mpack_write_u8(mpctx, diskid);

    mpack_write_cstr(mpctx, "desc");
    mpack_write_cstr(mpctx, "This is a demo disk");

    mpack_write_cstr(mpctx, "ctime");
    mpack_write_u32(mpctx, time(NULL));

    mpack_write_cstr(mpctx, "mtime");
    mpack_write_u32(mpctx, time(NULL));

    mpack_write_cstr(mpctx, "luns");
    mpack_write_array(mpctx, n_luns);
    for (i=0; i<n_luns; i++) {
        mpack_write_map(mpctx, 7);
        mpack_write_cstr(mpctx, "lunid");
        mpack_write_u16(mpctx, i);

        mpack_write_cstr(mpctx, "lun");
        mpack_write_u64(mpctx, i);

        mpack_write_cstr(mpctx, "crypt");
        mpack_write_true(mpctx);

        mpack_write_cstr(mpctx, "diskid");
        mpack_write_u8(mpctx, diskid);

        mpack_write_cstr(mpctx, "ctime");
        mpack_write_u32(mpctx, time(NULL));

        mpack_write_cstr(mpctx, "mtime");
        mpack_write_u32(mpctx, time(NULL));

        mpack_write_cstr(mpctx, "desc");
        mpack_write_cstr(mpctx, "This is a demo lun");
    }

    mpack_write_cstr(mpctx, "nics");
    mpack_write_array(mpctx, n_nics);
    for (i=0; i<n_nics; i++) {
        mpack_write_map(mpctx, 6);
        mpack_write_cstr(mpctx, "nicid");
        mpack_write_u8(mpctx, i);

        mpack_write_cstr(mpctx, "diskid");
        mpack_write_u8(mpctx, diskid);

        mpack_write_cstr(mpctx, "wwpn");
        mpack_write_cstr(mpctx, "50:06:0e:80:12:4f:ae:01");

        mpack_write_cstr(mpctx, "ctime");
        mpack_write_u32(mpctx, time(NULL));

        mpack_write_cstr(mpctx, "mtime");
        mpack_write_u32(mpctx, time(NULL));

        mpack_write_cstr(mpctx, "desc");
        mpack_write_cstr(mpctx, "This is a demo lun");
    }
}

int main(void)
{
    int i;
    mpack_ctx_t mpctx;
    stream_t *stream = NULL;

#if 1
    stream = stream_fopen("mpack.dat", "w");
    if (stream == NULL) {
        fprintf(stderr, "open file mpack.dat to write failed.\n");
        return -1;
    }
#else
    stream = stream_ramopen(malloc, realloc, free);
    if (stream == NULL) {
        fprintf(stderr, "open memory to write failed.\n");
        return -1;
    }
#endif

    mpack_init(&mpctx, stream, stream_reader, stream_writer);

    for (i=0; i<64; i++) {
        mpack_write_diskinfo(&mpctx, i, 1024, 64);
    }

    stream_close(stream);
    return 0;
}

