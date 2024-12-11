#ifndef LIBCRC32_H
#define LIBCRC32_H

#include <stdint.h>

extern uint32_t crc32_run(uint32_t initial, char* data, int len);

#endif
