#include "libstream.h"
#include "libmd5.h"

#include <errno.h>
#include <sys/mman.h>

typedef struct stream_file_st
{
    FILE* fp;
} stream_file_t;

typedef struct stream_mem_st
{
    char* mbuf;
    int mbuf_size;
    int content_size;
    int current_pos;
    void* (*malloc)(size_t size);
    void* (*realloc)(void* ptr, size_t size);
    void (*free)(void* ptr);
} stream_mem_t;

typedef struct stream_ops_st
{
    int (*read)(void* obj, char* buffer, int length);
    int (*write)(void* obj, char* buffer, int length);
    long (*seek)(void* obj, long offset, int whence);
    long (*tell)(void* obj);
    int (*flush)(void* obj);
    int (*close)(void* obj);
    void* (*address)(void* obj);
    int (*length)(void* obj);
    int (*eof)(void* obj);
} stream_ops_t;

#define STREAM_OPEN_READ 0x00000001
#define STREAM_OPEN_WRITE 0x00000002
struct stream_st
{
    uint32_t flags;
    stream_ops_t* ops;
    char obj[0];
};

static stream_t* stream_create(int obj_size)
{
    struct stream_st* pstream;

    pstream = malloc(sizeof(struct stream_st) + obj_size);
    if (pstream == NULL)
    {
        return NULL;
    }

    pstream->flags = 0;
    pstream->ops = NULL;

    return pstream;
}

static void stream_destroy(stream_t* stream)
{
    struct stream_st* pstream = stream;

    if (pstream)
    {
        free(pstream);
    }
}

static int stream_file_read(void* obj, char* buffer, int length)
{
    stream_file_t* file = (stream_file_t*)obj;

    return fread(buffer, 1, length, file->fp);
}

static int stream_file_write(void* obj, char* buffer, int length)
{
    stream_file_t* file = (stream_file_t*)obj;

    return fwrite(buffer, 1, length, file->fp);
}

static long stream_file_seek(void* obj, long offset, int whence)
{
    stream_file_t* file = (stream_file_t*)obj;

    return fseek(file->fp, offset, whence);
}

static long stream_file_tell(void* obj)
{
    stream_file_t* file = (stream_file_t*)obj;

    return ftell(file->fp);
}

static int stream_file_flush(void* obj)
{
    stream_file_t* file = (stream_file_t*)obj;

    return fflush(file->fp);
}

static int stream_file_close(void* obj)
{
    stream_file_t* file = (stream_file_t*)obj;

    fsync(fileno(file->fp));

    return fclose(file->fp);
}

static void* stream_file_address(void* obj) { return NULL; }

static int stream_file_length(void* obj)
{
    long offset, length;
    stream_file_t* file = (stream_file_t*)obj;

    /*
     * save the old cursor
     */
    offset = ftell(file->fp);

    fseek(file->fp, 0, SEEK_END);
    length = ftell(file->fp);

    /*
     * restore the old cursor
     */
    fseek(file->fp, offset, SEEK_SET);

    return length;
}

static int stream_file_eof(void* obj)
{
    stream_file_t* file = (stream_file_t*)obj;

    return feof(file->fp);
}

static int stream_mem_read(void* obj, char* buffer, int length)
{
    int left_length;
    stream_mem_t* mem = (stream_mem_t*)obj;

    if (mem == NULL || mem->mbuf == NULL)
    {
        return 0;
    }

    if (mem->current_pos > mem->content_size)
    {
        return 0;
    }

    left_length = mem->content_size - mem->current_pos;
    length = left_length < length ? left_length : length;
    memcpy(buffer, &mem->mbuf[mem->current_pos], length);
    mem->current_pos += length;

    return length;
}

static int stream_mem_write(void* obj, char* buffer, int length)
{
    int next_pos;
    stream_mem_t* mem = (stream_mem_t*)obj;

    next_pos = mem->current_pos + length;
    if (next_pos > mem->mbuf_size)
    {
        char* new_mbuf;
        int new_mbuf_size = mem->mbuf_size;

        if (mem->realloc == NULL)
        {
            return -ENOMEM;
        }

        while (new_mbuf_size < next_pos)
            new_mbuf_size += 32;
        new_mbuf = mem->realloc(mem->mbuf, new_mbuf_size);
        if (new_mbuf == NULL)
        {
            mem->free(mem->mbuf);
            mem->mbuf = NULL;
            return -ENOMEM;
        }
        mem->mbuf = new_mbuf;
        mem->mbuf_size = new_mbuf_size;
    }

    /** padding with zero from mem->content_size to mem->current_pos */
    if (mem->current_pos > mem->content_size)
    {
        memset(mem->mbuf + mem->content_size, 0,
               mem->current_pos - mem->content_size);
    }

    memcpy(mem->mbuf + mem->current_pos, buffer, length);
    mem->content_size = next_pos;
    mem->current_pos = next_pos;
    return length;
}

static long stream_mem_seek(void* obj, long offset, int whence)
{
    int newpos = 0;
    stream_mem_t* mem = (stream_mem_t*)obj;

    switch (whence)
    {
        case SEEK_SET:
            newpos = offset;
            break;
        case SEEK_END:
            newpos = mem->content_size - offset;
            break;
        case SEEK_CUR:
            newpos = mem->current_pos + offset;
            break;
        default:
            break;
    }

    if (newpos < 0 || newpos >= mem->content_size)
        return -EINVAL;

    mem->current_pos = newpos;
    return mem->current_pos;
}

static long stream_mem_tell(void* obj)
{
    stream_mem_t* mem = (stream_mem_t*)obj;

    return mem->current_pos;
}

static int stream_mem_flush(void* obj)
{
    stream_mem_t* mem = (stream_mem_t*)obj;

    mem->content_size = 0;
    mem->current_pos = 0;
    return 0;
}

static int stream_mem_close(void* obj)
{
    stream_mem_t* mem = (stream_mem_t*)obj;
    if (mem->free)
    {
        mem->free(mem->mbuf);
    }

    return 0;
}

static void* stream_mem_address(void* obj)
{
    stream_mem_t* mem = (stream_mem_t*)obj;

    return mem->mbuf;
}

static int stream_mem_length(void* obj)
{
    stream_mem_t* mem = (stream_mem_t*)obj;

    return mem->content_size;
}

static int stream_mem_eof(void* obj)
{
    stream_mem_t* mem = (stream_mem_t*)obj;

    return mem->current_pos == mem->content_size;
}

static stream_ops_t g_file_ops = {
    .read = stream_file_read,
    .write = stream_file_write,
    .seek = stream_file_seek,
    .tell = stream_file_tell,
    .flush = stream_file_flush,
    .close = stream_file_close,
    .address = stream_file_address,
    .length = stream_file_length,
    .eof = stream_file_eof,
};

static stream_ops_t g_mem_ops = {
    .read = stream_mem_read,
    .write = stream_mem_write,
    .seek = stream_mem_seek,
    .tell = stream_mem_tell,
    .flush = stream_mem_flush,
    .close = stream_mem_close,
    .address = stream_mem_address,
    .length = stream_mem_length,
    .eof = stream_mem_eof,
};

static int parse_openmode(char* s)
{
    int rwmode = 0;

    while (*s)
    {
        switch (*s)
        {
            case 'r':
                rwmode |= STREAM_OPEN_READ;
                break;
            case 'w':
            case 'a':
                rwmode |= STREAM_OPEN_WRITE;
                break;
            case '+':
                rwmode |= STREAM_OPEN_WRITE;
                rwmode |= STREAM_OPEN_READ;
                break;
            default:
                break;
        }
        s++;
    }

    return rwmode;
}

/**
 * @fn stream_fopen
 * @brief open a regular file
 */
stream_t* stream_fopen(char* filename, char* modes)
{
    stream_file_t* file;
    struct stream_st* pstream;

    pstream = stream_create(sizeof(stream_file_t));
    if (pstream == NULL)
    {
        return NULL;
    }

    pstream->ops = &g_file_ops;
    pstream->flags = parse_openmode(modes);

    file = (stream_file_t*)pstream->obj;
    if (filename == NULL || *filename == '\0')
    {
        if (pstream->flags & STREAM_OPEN_WRITE)
        {
            file->fp = stdout;
        }
        else if (pstream->flags & STREAM_OPEN_READ)
        {
            file->fp = stdin;
        }
    }
    else
    {
        file->fp = fopen(filename, modes);
        if (file->fp == NULL)
        {
            stream_destroy(pstream);
            return NULL;
        }
    }

    return pstream;
}

stream_t* stream_tmpopen(void)
{
    stream_file_t* file;
    struct stream_st* pstream;

    pstream = stream_create(sizeof(stream_file_t));
    if (pstream == NULL)
    {
        return NULL;
    }

    pstream->ops = &g_file_ops;
    pstream->flags = STREAM_OPEN_READ | STREAM_OPEN_WRITE;

    file = (stream_file_t*)pstream->obj;

    /**
     * the file will be automatically deleted when it is closed
     */
    file->fp = tmpfile();
    if (file->fp == NULL)
    {
        stream_destroy(pstream);
        return NULL;
    }

    return pstream;
}

stream_t* stream_ramopen(void* (*user_malloc)(size_t size),
                         void* (*user_realloc)(void* ptr, size_t size),
                         void (*user_free)(void* ptr))
{
    stream_mem_t* mem;
    struct stream_st* pstream;

    if (user_malloc == NULL || user_realloc == NULL || user_free == NULL)
    {
        return NULL;
    }

    pstream = stream_create(sizeof(stream_mem_t));
    if (pstream == NULL)
    {
        return NULL;
    }

    pstream->ops = &g_mem_ops;
    pstream->flags = STREAM_OPEN_READ | STREAM_OPEN_WRITE;

    mem = (stream_mem_t*)pstream->obj;

    mem->malloc = user_malloc;
    mem->realloc = user_realloc;
    mem->free = user_free;

    mem->mbuf = mem->malloc(256);
    if (mem->mbuf == NULL)
    {
        stream_destroy(pstream);
        return NULL;
    }

    mem->mbuf_size = 256;
    mem->content_size = 0;
    mem->current_pos = 0;

    return pstream;
}

stream_t* stream_romopen(void* data, int data_len)
{
    stream_mem_t* mem;
    struct stream_st* pstream;

    pstream = stream_create(sizeof(stream_mem_t));
    if (pstream == NULL)
    {
        return NULL;
    }

    pstream->ops = &g_mem_ops;
    pstream->flags = STREAM_OPEN_READ;

    mem = (stream_mem_t*)pstream->obj;

    mem->mbuf = data;
    mem->mbuf_size = data_len;
    mem->content_size = data_len;
    mem->current_pos = 0;
    mem->malloc = NULL;
    mem->realloc = NULL;
    mem->free = NULL;

    return pstream;
}

int stream_romset(stream_t* stream, void* data, int data_len)
{
    stream_mem_t* mem;
    struct stream_st* pstream = stream;

    mem = (stream_mem_t*)pstream->obj;

    mem->mbuf = data;
    mem->mbuf_size = data_len;
    mem->content_size = data_len;
    mem->current_pos = 0;

    return 0;
}

stream_t* stream_memopen(void* data, int data_len)
{
    stream_mem_t* mem;
    struct stream_st* pstream;

    pstream = stream_create(sizeof(stream_mem_t));
    if (pstream == NULL)
    {
        return NULL;
    }

    pstream->ops = &g_mem_ops;
    pstream->flags = STREAM_OPEN_READ | STREAM_OPEN_WRITE;

    mem = (stream_mem_t*)pstream->obj;

    mem->mbuf = data;
    mem->mbuf_size = data_len;
    mem->content_size = 0;
    mem->current_pos = 0;
    mem->malloc = NULL;
    mem->realloc = NULL;
    mem->free = NULL;

    return pstream;
}

int stream_memset(stream_t* stream, void* data, int data_len)
{
    stream_mem_t* mem;
    struct stream_st* pstream = stream;

    if (data == NULL || data_len == 0)
    {
        return -EINVAL;
    }

    mem = (stream_mem_t*)pstream->obj;

    mem->mbuf = data;
    mem->mbuf_size = data_len;
    mem->content_size = 0;
    mem->current_pos = 0;

    return 0;
}

void stream_flush(stream_t* stream)
{
    struct stream_st* pstream = stream;

    if (pstream)
    {
        pstream->ops->flush(pstream->obj);
    }

    return;
}

void stream_close(stream_t* stream)
{
    struct stream_st* pstream = stream;

    if (pstream)
    {
        pstream->ops->close(pstream->obj);
        stream_destroy(pstream);
    }

    return;
}

void* stream_address(stream_t* stream)
{
    struct stream_st* pstream = stream;

    if (pstream == NULL)
    {
        return NULL;
    }

    return pstream->ops->address(pstream->obj);
}

int stream_length(stream_t* stream)
{
    struct stream_st* pstream = stream;

    if (pstream == NULL)
    {
        return -EINVAL;
    }

    return pstream->ops->length(pstream->obj);
}

int stream_eof(stream_t* stream)
{
    struct stream_st* pstream = stream;

    if (pstream == NULL)
    {
        return 1;
    }

    return pstream->ops->eof(pstream->obj);
}

int stream_seek(stream_t* stream, long offset, int whence)
{
    struct stream_st* pstream = stream;

    if (pstream == NULL)
    {
        return -EINVAL;
    }

    return pstream->ops->seek(pstream->obj, offset, whence);
}

long stream_rewind(stream_t* stream)
{
    struct stream_st* pstream = stream;

    if (pstream == NULL)
    {
        return -EINVAL;
    }

    return pstream->ops->seek(pstream->obj, 0, SEEK_SET);
}

long stream_tell(stream_t* stream)
{
    struct stream_st* pstream = stream;

    if (pstream == NULL)
    {
        return -EINVAL;
    }

    return pstream->ops->tell(pstream->obj);
}

/*******************************************************\
 Code for reading and writing streams.
\*******************************************************/

int stream_read(stream_t* stream, char* buffer, int length)
{
    struct stream_st* pstream = stream;

    if (pstream == NULL || buffer == NULL)
    {
        return -EINVAL;
    }

    if ((pstream->flags & STREAM_OPEN_READ) == 0)
    {
        return -EINVAL;
    }

    return pstream->ops->read(pstream->obj, buffer, length);
}

int stream_read8(stream_t* stream, char* buffer)
{
    return stream_read(stream, buffer, 1);
}

int stream_unread8(stream_t* stream)
{
    return stream_seek(stream, -1, SEEK_CUR);
}

int stream_read16(stream_t* stream, char* buffer)
{
    return stream_read(stream, buffer, 2);
}

int stream_unread16(stream_t* stream)
{
    return stream_seek(stream, -2, SEEK_CUR);
}

int stream_read32(stream_t* stream, char* buffer)
{
    return stream_read(stream, buffer, 4);
}

int stream_unread32(stream_t* stream)
{
    return stream_seek(stream, -4, SEEK_CUR);
}

int stream_read64(stream_t* stream, char* buffer)
{
    return stream_read(stream, buffer, 8);
}

int stream_unread64(stream_t* stream)
{
    return stream_seek(stream, -8, SEEK_CUR);
}

int stream_write(stream_t* stream, char* buffer, int length)
{
    struct stream_st* pstream = stream;

    if (pstream == NULL || buffer == NULL)
    {
        return -EINVAL;
    }

    if ((pstream->flags & STREAM_OPEN_WRITE) == 0)
    {
        return -EINVAL;
    }

    return pstream->ops->write(pstream->obj, buffer, length);
}

int stream_write8(stream_t* stream, char* buffer)
{
    return stream_write(stream, buffer, 1);
}

int stream_unwrite8(stream_t* stream)
{
    return stream_seek(stream, -1, SEEK_CUR);
}

int stream_write16(stream_t* stream, char* buffer)
{
    return stream_write(stream, buffer, 2);
}

int stream_unwrite16(stream_t* stream)
{
    return stream_seek(stream, -2, SEEK_CUR);
}

int stream_write32(stream_t* stream, char* buffer)
{
    return stream_write(stream, buffer, 4);
}

int stream_unwrite32(stream_t* stream)
{
    return stream_seek(stream, -4, SEEK_CUR);
}

int stream_write64(stream_t* stream, char* buffer)
{
    return stream_write(stream, buffer, 8);
}

int stream_unwrite64(stream_t* stream)
{
    return stream_seek(stream, -8, SEEK_CUR);
}

int stream_getc(stream_t* stream)
{
    char c;
    int ret;

    ret = stream_read8(stream, &c);
    if (ret < 0)
    {
        return ret;
    }

    /*
     * return EOF(-1) when end of file.
     */
    if (ret == 0)
    {
        return EOF;
    }

    /*
     * Warning! return c directly might return a negative number.
     */
    return (int)(c & 0xFF);
}

int stream_ungetc(stream_t* stream)
{
    return stream_seek(stream, -1, SEEK_CUR);
}

int stream_putc(stream_t* stream, char c) { return stream_write8(stream, &c); }

int stream_unputc(stream_t* stream)
{
    return stream_seek(stream, -1, SEEK_CUR);
}

/**
 * read a line from current position of the given stream,
 * note that you must check the return pointer <string> is
 * non-null before using this return buffer, and you NEED
 * to free this buffer after use it.
 *
 * we will replace the line feed(CR or LF or CR/LF) with
 * a string terminal '\0'.
 *
 * */
int stream_gets(stream_t* stream, char** string)
{
    char c;
    char *rdbuf, *newbuf;
    int rdlen;

    if (stream == NULL || string == NULL)
    {
        return -EINVAL;
    }

    rdlen = 0;
    rdbuf = NULL;
    while (stream_read8(stream, &c) == 1)
    {
        newbuf = realloc(rdbuf, (rdlen + 1) * sizeof(char));
        if (newbuf == NULL)
        {
            free(rdbuf);
            return -ENOMEM;
        }

        rdlen += 1;
        rdbuf = newbuf;
        *(rdbuf + rdlen - 1) = c;

        if (c == '\n')
        {
            *(rdbuf + rdlen - 1) =
                '\0'; /* replace the LF with the terminator. */
            break;
        }

        if (c == '\r')
        {
            *(rdbuf + rdlen - 1) =
                '\0'; /* replace the CR with the terminator. */

            /* for DOS/WINDOWS, skip the next LF char. */
            if (stream_read8(stream, &c) == 0)
            {
                break;
            }

            if (c == '\n')
            {
                break;
            }
            else
            {
                stream_seek(stream, -1, SEEK_CUR);
                break;
            }
        }
    }

    *string = rdbuf;
    return rdlen - 1;
}

/**
 * write a number of characters in the string into the stream.
 * the string terminal '\0' will not be written into.
 * */
int stream_puts(stream_t* stream, char* string)
{
    int cnt;
    int wrlen;
    char* p;

    if (stream == NULL || string == NULL)
    {
        return -EINVAL;
    }

    cnt = 0;
    for (p = string; *p; p++)
    {
        wrlen = stream_write8(stream, p);
        if (wrlen <= 0)
        {
            return -EIO;
        }

        cnt += wrlen;
    }

    return cnt;
}

int stream_printf(stream_t* stream, char* fmt, ...)
{
    va_list ap;
    char buf[1024] = {
        0,
    };

    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    return stream_puts(stream, buf);
}

int stream_copy(stream_t* dst, stream_t* src)
{
    int rdsize, wrsize, totalcopy;
    char buffer[4096] = {
        0,
    };

    if (dst == NULL || src == NULL)
    {
        return -EINVAL;
    }

    totalcopy = 0;
    while (1)
    {
        rdsize = stream_read(src, buffer, sizeof(buffer));
        if (rdsize < 0)
        {
            return -EIO;
        }

        if (rdsize == 0)
        {
            break;
        }

        wrsize = stream_write(dst, buffer, rdsize);
        if (wrsize < 0 || wrsize != rdsize)
        {
            return -EIO;
        }

        totalcopy += wrsize;
    }

    return totalcopy;
}

int stream_ncopy(stream_t* dst, stream_t* src, int length)
{
    int rdsize, wrsize, totalcopy, readlen;
    char buffer[4096] = {
        0,
    };

    if (dst == NULL || src == NULL || length == 0)
    {
        return -EINVAL;
    }

    totalcopy = 0;
    while (totalcopy < length)
    {
        if (length - totalcopy < 4096)
            readlen = length - totalcopy;
        else
            readlen = sizeof(buffer);

        rdsize = stream_read(src, buffer, readlen);
        if (rdsize < 0)
        {
            return -EIO;
        }

        if (rdsize == 0)
        {
            break;
        }

        wrsize = stream_write(dst, buffer, rdsize);
        if (wrsize < 0 || wrsize != rdsize)
        {
            return -EIO;
        }

        totalcopy += wrsize;
    }

    return totalcopy;
}

int stream_md5(stream_t* stream, uint8_t digest[16])
{
    int len;
    int filelen = 0;
    md5ctx_t ctx;
    uint8_t buf[1024] = {
        0,
    };

    memset(digest, 0, 16);

    md5_init(&ctx);
    while ((len = stream_read(stream, (char*)buf, sizeof(buf))) > 0)
    {
        md5_update(&ctx, buf, len);
        filelen += len;
    }
    md5_final(&ctx, digest);

    return filelen;
}

int stream_md5hex(stream_t* stream, char* dighex, int size)
{
    int i;
    int offset = 0;
    int filelen = 0;
    uint8_t digest[16] = {
        0,
    };

    if (size < 33)
    {
        return -EINVAL;
    }

    filelen = stream_md5(stream, digest);
    for (i = 0; i < 16; i++)
    {
        offset += snprintf(dighex + offset, size - offset, "%02X", digest[i]);
    }

    return filelen;
}

int stream_save(stream_t* stream, char* filename)
{
    int len;
    int cursor;

    stream_t* output = stream_fopen(filename, "w");
    if (output == NULL)
    {
        return -EINVAL;
    }

    cursor = stream_tell(stream);

    stream_rewind(stream);
    len = stream_copy(output, stream);

    stream_seek(stream, cursor, SEEK_SET);

    stream_close(output);
    return len;
}

int stream_dump(stream_t* stream)
{
    int i;
    int len;
    int cursor;
    int filelen = 0;
    uint8_t buf[1024] = {
        0,
    };

    cursor = stream_tell(stream);

    stream_rewind(stream);

    printf("stream %p length %d:\n", stream_address(stream),
           stream_length(stream));
    while ((len = stream_read(stream, (char*)buf, sizeof(buf))) > 0)
    {
        for (i = 0; i < len; i++)
        {
            fprintf(stderr, "%02x ", buf[i]);
            if (i % 16 == 15)
            {
                fprintf(stderr, "\n");
            }
        }

        filelen += len;
    }
    fprintf(stderr, "\n");

    stream_seek(stream, cursor, SEEK_SET);
    return filelen;
}

int stream_append(char* path, int limit, char* fmt, ...)
{
    int len = 0;
    FILE* fp = NULL;
    char* buf = NULL;
    va_list ap;

    fp = fopen(path, "a+");
    if (fp == NULL)
    {
        return -ENOENT;
    }

    if (limit > 0)
    {
        fseek(fp, 0, SEEK_END);
        len = ftell(fp);
        fseek(fp, 0, SEEK_SET);
        setvbuf(fp, NULL, _IONBF, 0);

        if (len >= limit)
        {
            fclose(fp);
            unlink(path);
            fp = fopen(path, "a+");
            if (fp == NULL)
            {
                return -ENOENT;
            }
        }
    }

    va_start(ap, fmt);
    len = vasprintf(&buf, fmt, ap);
    va_end(ap);

    if (len < 0)
    {
        fclose(fp);
        return -1;
    }

    if (fwrite(buf, 1, len, fp) < 0)
    {
        fclose(fp);
        free(buf);
        return -EIO;
    }

    fclose(fp);
    free(buf);
    return 0;
}
