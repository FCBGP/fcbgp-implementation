#ifndef STREAM_H
#define STREAM_H 1

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef void stream_t;

/* libstream.c */
extern stream_t* stream_fopen(char* filename, char* modes);
extern stream_t* stream_tmpopen(void);
extern stream_t* stream_ramopen(void* (*user_malloc)(size_t size),
                                void* (*user_realloc)(void* ptr, size_t size),
                                void (*user_free)(void* ptr));
extern stream_t* stream_romopen(void* data, int data_len);
extern stream_t* stream_memopen(void* data, int data_len);
extern int stream_romset(stream_t* stream, void* data, int data_len);
extern int stream_memset(stream_t* stream, void* data, int data_len);
extern void stream_flush(stream_t* stream);
extern void stream_close(stream_t* stream);
extern void* stream_address(stream_t* stream);
extern int stream_length(stream_t* stream);
extern int stream_eof(stream_t* stream);
extern int stream_seek(stream_t* stream, long offset, int whence);
extern long stream_rewind(stream_t* stream);
extern long stream_tell(stream_t* stream);
extern int stream_read(stream_t* stream, char* buffer, int length);
extern int stream_read8(stream_t* stream, char* buffer);
extern int stream_unread8(stream_t* stream);
extern int stream_read16(stream_t* stream, char* buffer);
extern int stream_unread16(stream_t* stream);
extern int stream_read32(stream_t* stream, char* buffer);
extern int stream_unread32(stream_t* stream);
extern int stream_read64(stream_t* stream, char* buffer);
extern int stream_unread64(stream_t* stream);
extern int stream_write(stream_t* stream, char* buffer, int length);
extern int stream_write8(stream_t* stream, char* buffer);
extern int stream_unwrite8(stream_t* stream);
extern int stream_write16(stream_t* stream, char* buffer);
extern int stream_unwrite16(stream_t* stream);
extern int stream_write32(stream_t* stream, char* buffer);
extern int stream_unwrite32(stream_t* stream);
extern int stream_write64(stream_t* stream, char* buffer);
extern int stream_unwrite64(stream_t* stream);
extern int stream_getc(stream_t* stream);
extern int stream_ungetc(stream_t* stream);
extern int stream_putc(stream_t* stream, char c);
extern int stream_unputc(stream_t* stream);
extern int stream_gets(stream_t* stream, char** string);
extern int stream_puts(stream_t* stream, char* string);
extern int stream_printf(stream_t* stream, char* fmt, ...);
extern int stream_copy(stream_t* dst, stream_t* src);
extern int stream_ncopy(stream_t* dst, stream_t* src, int length);
extern int stream_md5(stream_t* stream, uint8_t digest[16]);
extern int stream_md5hex(stream_t* stream, char* dighex, int size);
extern int stream_save(stream_t* stream, char* filename);
extern int stream_dump(stream_t* stream);
extern int stream_append(char* path, int limit, char* fmt, ...);

#endif
