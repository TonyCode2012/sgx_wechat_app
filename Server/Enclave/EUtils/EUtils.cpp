#include "EUtils.h"

static char *_hex_buffer = NULL;
static size_t _hex_buffer_size = 0;
const char _hextable[] = "0123456789abcdef";

/**
 * @description: use ocall_print_string to print format string
 * @return: the length of printed string
 */
int eprintf(const char *fmt, ...)
{
	char buf[BUFSIZE] = {'\0'};
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(buf, BUFSIZE, fmt, ap);
	va_end(ap);
	ocall_print_string(buf);
	return (int)strnlen(buf, BUFSIZE - 1) + 1;
}

/**
 * @description: use ocall_eprint_string to print format string
 * @return: the length of printed string
 */
int feprintf(const char *fmt, ...)
{
	char buf[BUFSIZE] = {'\0'};
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(buf, BUFSIZE, fmt, ap);
	va_end(ap);
	ocall_eprint_string(buf);
	return (int)strnlen(buf, BUFSIZE - 1) + 1;
}

/**
 * @description: Change char to int
 * @return: Corresponding int
 * */
int char_to_int(char input)
{
	if (input >= '0' && input <= '9')
		return input - '0';
	if (input >= 'A' && input <= 'F')
		return input - 'A' + 10;
	if (input >= 'a' && input <= 'f')
		return input - 'a' + 10;
	return 0;
}

/**
 * @description: Transform string to hexstring
 * @param vsrc -> Source byte array
 * @param len -> Srouce byte array length
 * @return: Hexstringed data
 * */
char *hexstring(const void *vsrc, size_t len)
{
	size_t i, bsz;
	const unsigned char *src = (const unsigned char *)vsrc;
	char *bp;

	bsz = len * 2 + 1; /* Make room for NULL byte */
	if (bsz >= _hex_buffer_size)
	{
		/* Allocate in 1K increments. Make room for the NULL byte. */
		size_t newsz = 1024 * (bsz / 1024) + ((bsz % 1024) ? 1024 : 0);
		_hex_buffer_size = newsz;
		_hex_buffer = (char *)realloc(_hex_buffer, newsz);
		if (_hex_buffer == NULL)
		{
			return NULL;
		}
	}

	for (i = 0, bp = _hex_buffer; i < len; ++i)
	{
		*bp = (uint8_t)_hextable[src[i] >> 4];
		++bp;
		*bp = (uint8_t)_hextable[src[i] & 0xf];
		++bp;
	}
	_hex_buffer[len * 2] = 0;

	return _hex_buffer;
}

/**
 * @description: Convert hexstring to bytes array, note that
 * the size of got data is half of len
 * @param src -> Source char*
 * @param len -> Source char* length
 * @return: Bytes array
 * */
uint8_t *hex_string_to_bytes(const char *src, size_t len)
{
    if (len % 2 != 0)
    {
        return NULL;
    }

    uint8_t *p_target;
    uint8_t *target = (uint8_t *)malloc(len / 2);
    if (target == NULL)
    {
        return NULL;
    }
	memset(target, 0, len / 2);
    p_target = target;
    while (*src && src[1])
    {
        *(target++) = (uint8_t)(char_to_int(*src) * 16 + char_to_int(src[1]));
        src += 2;
    }

    return p_target;
}
