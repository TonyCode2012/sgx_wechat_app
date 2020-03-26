#ifndef _CRUST_E_UTILS_H_
#define _CRUST_E_UTILS_H_

#include <assert.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <string>
#include <vector>
#include "Enclave_t.h"

/* Main loop waiting time (us) */
#define MAIN_LOOP_WAIT_TIME 10000000
#define BUFSIZE 100000


#if defined(__cplusplus)
extern "C"
{
#endif

int eprintf(const char* fmt, ...);
int feprintf(const char* fmt, ...);
char *hexstring(const void *vsrc, size_t len);
uint8_t *hex_string_to_bytes(const char *src, size_t len);

#if defined(__cplusplus)
}
#endif

#endif /* !_CRUST_E_UTILS_H_ */
