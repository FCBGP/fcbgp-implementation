/********************************************************************************
* File Name:    test_base64.c
* Author:       basilguo@163.com
* Created Time: 2023-10-09 03:15:14
* Description:
********************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>

int base64_encode(const unsigned char *buffer, size_t length, char ** b64text)
{
    BIO *bio, *b64;
    BUF_MEM *buffer_ptr;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    // ignore new lines - write everything in one line
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, buffer, length);
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &buffer_ptr);
    BIO_set_close(bio, BIO_NOCLOSE);
    BIO_free_all(bio);

    *b64text = (*buffer_ptr).data;

    return 0;
}

static size_t calc_decode_len(const char *b64input)
{
    size_t len = strlen(b64input);
    size_t padding = 0;

    if (b64input[len-1] == '=' && b64input[len-2] == '=')
        padding = 2;
    else if (b64input[len-1] == '=')
        padding = 1;

    return (len * 3) / 4 - padding;
}

int base64_decode(char *b64msg, unsigned char **buffer, size_t *length)
{
    BIO *bio, *b64;
    int decode_len = calc_decode_len(b64msg);

    *buffer = (unsigned char *) malloc(decode_len + 1);
    (*buffer)[decode_len] = '\0';

     bio = BIO_new_mem_buf(b64msg, -1);
     b64 = BIO_new(BIO_f_base64());
     bio = BIO_push(b64, bio);

     BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
     *length = BIO_read(bio, *buffer, strlen(b64msg));
     assert(*length == decode_len);

     BIO_free_all(bio);

     return 0;
}

int main(int argc, char *argv[])
{
    // encode
    char *b64_encode_output, *text = "Hello world!";
    base64_encode(text, strlen(text), &b64_encode_output);
    printf("Encode\n");
    printf("\tInput:  %s\n", text);
    printf("\tOutput: %s\n", b64_encode_output);

    // decode
    unsigned char * b64_decode_output;
    size_t b64_decode_output_len;
    base64_decode(b64_encode_output, &b64_decode_output,
            &b64_decode_output_len);
    printf("Decode:\n");
    printf("\tInput:  %s\n", b64_encode_output);
    printf("\tOutput: %s\n", b64_decode_output);
    return 0;
}
