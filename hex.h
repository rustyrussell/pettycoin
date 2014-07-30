#ifndef PETTYCOIN_HEX_H
#define PETTYCOIN_HEX_H
#include "config.h"
#include <ccan/tal/tal.h>
#include <stdbool.h>

/* Unpack slen hex digits into buf; fail on bad char or not exact length */
bool from_hex(const char *str, size_t slen, void *buf, size_t bufsize);

/* Allocate hex string off ctx */
char *to_hex(const tal_t *ctx, const void *buf, size_t bufsize);

/* dest becomes nul terminated string, returns bufsize used. */
size_t to_hex_direct(char *dest, size_t destlen,
		     const void *buf, size_t bufsize);

#endif /* PETTYCOIN_HEX_H */
