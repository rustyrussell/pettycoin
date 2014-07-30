#include "hex.h"
#include <assert.h>
#include <ccan/short_types/short_types.h>
#include <stdio.h>

static bool char_to_hex(u8 *val, char c)
{
	if (c >= '0' && c <= '9') {
		*val = c - '0';
		return true;
	}
 	if (c >= 'a' && c <= 'f') {
		*val = c - 'a' + 10;
		return true;
	}
 	if (c >= 'A' && c <= 'F') {
		*val = c - 'A' + 10;
		return true;
	}
	return false;
}

bool from_hex(const char *str, size_t slen, void *buf, size_t bufsize)
{
	u8 v1, v2;
	u8 *p = buf;

	while (slen > 1) {
		if (!char_to_hex(&v1, str[0]) || !char_to_hex(&v2, str[1]))
			return false;
		if (!bufsize)
			return false;
		*(p++) = (v1 << 4) | v2;
		str += 2;
		slen -= 2;
		bufsize--;
	}
	return slen == 0 && bufsize == 0;
}

static char hexchar(unsigned int val)
{
	if (val < 10)
		return '0' + val;
	if (val < 16)
		return 'a' + val - 10;
	abort();
}

size_t to_hex_direct(char *dest, size_t destlen,
		     const void *buf, size_t bufsize)
{
	size_t used = 0;

	/* Need room for nul terminator */
	assert(destlen > 0);

	while (destlen >= 3 && used < bufsize) {
		unsigned int c = ((const unsigned char *)buf)[used];
		*(dest++) = hexchar(c >> 4);
		*(dest++) = hexchar(c & 0xF);
		destlen -= 2;
		used++;
	}
	*dest = '\0';

	return used;
}

char *to_hex(const tal_t *ctx, const void *buf, size_t bufsize)
{
	char *hex = tal_arr(ctx, char, bufsize * 2 + 1);

	to_hex_direct(hex, bufsize * 2 + 1, buf, bufsize);

	return hex;
}
