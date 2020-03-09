#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <string.h>

int char_to_int(char input);
uint8_t *hex_string_to_bytes(const char *src, size_t len);
void print_hexstring(FILE *fp, const void *vsrc, size_t len);
char *hexstring(const void *vsrc, size_t len);
char *base64_encode(const char *msg, size_t sz);
char *base64_decode(const char *msg, size_t *sz);
uint8_t *switch_endian(const uint8_t *src, size_t sz);
int from_hexstring (unsigned char *dest, const void *vsrc, size_t len);
