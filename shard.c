#include "addr.h"
#include "shard.h"
#include "tx.h"
#include <stdlib.h>

/* This must match the order used in tx_cmp */
u32 shard_of_tx(const union protocol_tx *tx, u8 shard_order)
{
	const struct protocol_address *addr;
	struct protocol_address tmp;
	
	switch (tx_type(tx)) {
	case TX_NORMAL:
		pubkey_to_addr(&tx->normal.input_key, &tmp);
		addr = &tmp;
		goto known;
	case TX_FROM_GATEWAY:
		addr = &get_gateway_outputs(&tx->gateway)[0].output_addr;
		goto known;
	}
	abort();

known:
	return shard_of(addr, shard_order);
}
