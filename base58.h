#ifndef PETTYCOIN_BASE58_H
#define PETTYCOIN_BASE58_H
#include "config.h"
#include "protocol.h"
#include <ccan/tal/tal.h>
#include <openssl/bn.h>
#include <openssl/ripemd.h>
#include <stdbool.h>
#include <stdlib.h>

/* Encoding is version byte + ripemd160 + 4-byte checksum == 200 bits => 2^200.
 *
 * Now, 58^34 < 2^200, but 58^35 > 2^200.  So 35 digits is sufficient,
 * plus 1 terminator.
 */
#define BASE58_ADDR_MAX_LEN 36

/* Pettycoin address encoded in base58, with version and checksum */
char *pettycoin_to_base58(const tal_t *ctx, bool test_net,
			  const struct protocol_address *addr,
			  bool bitcoin_style);
bool pettycoin_from_base58(bool *test_net,
			   struct protocol_address *addr,
			   const char *base58);

bool ripemd_from_base58(u8 *version, u8 ripemd160[RIPEMD160_DIGEST_LENGTH],
			const char *base58);

char *base58_with_check(char dest[BASE58_ADDR_MAX_LEN],
			u8 buf[1 + RIPEMD160_DIGEST_LENGTH + 4]);

bool raw_decode_base58(BIGNUM *bn, const char *src);
void base58_get_checksum(u8 csum[4], const u8 buf[], size_t buflen);

#endif /* PETTYCOIN_BASE58_H */