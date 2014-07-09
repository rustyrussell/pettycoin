#ifndef PETTYCOIN_SSLERRORSTRING_H
#define PETTYCOIN_SSLERRORSTRING_H
#include "config.h"
#include <openssl/err.h>

static inline const char *ssl_error_string(void)
{
	static char errbuf[120];
        unsigned long e = ERR_get_error();

	/* There can be multiple errors: drain the rest. */
	while (ERR_get_error());

	return ERR_error_string(e, errbuf);
}

#endif /* PETTYCOIN_SSLERRORSTRING_H */
