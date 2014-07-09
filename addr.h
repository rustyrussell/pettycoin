#ifndef PETTYCOIN_ADDR_H
#define PETTYCOIN_ADDR_H
#include "config.h"
#include "protocol.h"

static inline void pubkey_to_addr(const struct protocol_pubkey *key,
				  struct protocol_address *addr)
{
	SHA256_CTX ctx;
	u8 sha[SHA256_DIGEST_LENGTH];

	SHA256_Init(&ctx);
	SHA256_Update(&ctx, key->key, sizeof(key->key));
	SHA256_Final(sha, &ctx);

	RIPEMD160(sha, sizeof(sha), addr->addr);
}

#endif /* PETTYCOIN_ADDR_H */
