#ifndef PETTYCOIN_ADDR_H
#define PETTYCOIN_ADDR_H
#include "protocol.h"

static inline void pubkey_to_addr(const struct protocol_pubkey *key,
				  struct protocol_address *addr)
{
	RIPEMD160(key->key, sizeof(key->key), addr->addr);
}

#endif /* PETTYCOIN_ADDR_H */
