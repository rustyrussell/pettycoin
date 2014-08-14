#ifndef PETTYCOIN_BASE58_H
#define PETTYCOIN_BASE58_H
#include "config.h"
#include "protocol.h"
#include <ccan/tal/tal.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ripemd.h>
#include <stdbool.h>
#include <stdlib.h>

/* Encoding is version byte + ripemd160 + 4-byte checksum == 200 bits => 2^200.
 *
 * Now, 58^34 < 2^200, but 58^35 > 2^200.  So 35 digits is sufficient,
 * plus 1 terminator.
 */
#define BASE58_ADDR_MAX_LEN 36

/* For encoding private keys, it's 302 bits.
 * 58^51 < 2^302, but 58^52 > 2^302.  So 52 digits, plus one terminator. */
#define BASE58_KEY_MAX_LEN 53

#define PETTY_PREFIX		 56
#define PETTY_PREFIX_TESTNET	 120

/* Pettycoin address encoded in base58, with version and checksum */
char *pettycoin_to_base58(const tal_t *ctx, bool test_net,
			  const struct protocol_address *addr,
			  bool bitcoin_style);
bool pettycoin_from_base58(bool *test_net,
			   struct protocol_address *addr,
			   const char *base58, size_t len);

bool ripemd_from_base58(u8 *version, u8 ripemd160[RIPEMD160_DIGEST_LENGTH],
			const char *base58);

char *base58_with_check(char dest[BASE58_ADDR_MAX_LEN],
			u8 buf[1 + RIPEMD160_DIGEST_LENGTH + 4]);

char *key_to_base58(const tal_t *ctx, bool test_net, EC_KEY *key,
		    bool bitcoin_style);
EC_KEY *key_from_base58(const char *base58, size_t base58_len,
			bool *test_net, struct protocol_pubkey *key);

bool raw_decode_base_n(BIGNUM *bn, const char *src, size_t len, int base);
bool raw_decode_base58(BIGNUM *bn, const char *src, size_t len);
void base58_get_checksum(u8 csum[4], const u8 buf[], size_t buflen);

#endif /* PETTYCOIN_BASE58_H */
