#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <inttypes.h>
#include <errno.h>
#include <time.h>

#include "libstream.h"
#include "libmsgpack.h"

int main(int argc, char *argv[])
{
    int optind = 1;
    int formated = 0;
    mpack_ctx_t mpctx;
    stream_t *input = NULL;
    stream_t *output = NULL;

    while (1) {
        if (optind >= argc) break;

        if (strcmp(argv[optind], "--help") == 0) {
            printf("Usage: %s [--input <intput>] [--output <output>] [--format]\n", argv[0]);
            return 0;
        }

        if (strcmp(argv[optind], "--format") == 0) {
            formated = 1;
            optind++;
        }

        if (optind >= argc) break;

        if (strcmp(argv[optind], "--input") == 0) {
            optind++;
            if (optind >= argc) {
                fprintf(stderr, "missing argument for --input.\n");
                return -1;
            }

            input = stream_fopen(argv[optind], "r");
            if (input == NULL) {
                fprintf(stderr, "open file %s to read failed.\n", argv[optind]);
                return -1;
            }

            optind++;
        }

        if (optind >= argc) break;

        if (strcmp(argv[optind], "--output") == 0) {
            optind++;
            if (optind >= argc) {
                fprintf(stderr, "missing argument for --output.\n");
                return -1;
            }

            output = stream_fopen(argv[optind], "w");
            if (input == NULL) {
                fprintf(stderr, "open file %s to write failed.\n", argv[optind]);
                return -1;
            }

            optind++;
        }
    }

    if (input == NULL) {
        input = stream_fopen(NULL, "r");
    }

    if (output == NULL) {
        output = stream_fopen(NULL, "w");
    }

    mpack_init(&mpctx, input, mpack_stream_reader, NULL);

    while (!stream_eof(input)) {
        mpack_ctx_dump(output, &mpctx, formated);
    }

    stream_close(input);
    stream_close(output);
    return 0;
}

