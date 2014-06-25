#include "shard.h"
#include "addr.h"
#include <stdlib.h>

/* This must match the order used in transaction_cmp */
u32 shard_of_tx(const union protocol_transaction *tx, u8 shard_order)
{
	const struct protocol_address *addr;
	struct protocol_address tmp;
	
	switch (tx->hdr.type) {
	case TRANSACTION_NORMAL:
		pubkey_to_addr(&tx->normal.input_key, &tmp);
		addr = &tmp;
		break;
	case TRANSACTION_FROM_GATEWAY:
		addr = &tx->gateway.output[0].output_addr;
		break;
	default:
		abort();
	}

	return shard_of(addr, shard_order);
}
