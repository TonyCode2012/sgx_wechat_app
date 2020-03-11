#include "OCalls.h"
#include "Common.h"

extern FILE *felog;

void ocall_print_string(const char *str)
{
    printf("%s", str);
}

void ocall_eprint_string(const char *str)
{
    printf_info(felog, "%s", str);
}
