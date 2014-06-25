#ifndef PETTYCOIN_SHARD_H
#define PETTYCOIN_SHARD_H
#include "protocol.h"
#include <string.h>

/* Shard of an address is the top shard_order bits */
static inline u16 shard_of(const struct protocol_address *addr, u8 shard_order)
{
	be16 shard;

	memcpy(&shard, addr->addr, sizeof(shard));
	return be16_to_cpu(shard) >> (16 - shard_order);
}

struct block;

u32 shard_of_tx(const union protocol_transaction *tx, u8 shard_order);

/* FIXME: voting mechanism to bump shard_order. */
static inline u8 next_shard_order(const struct block *prev)
{
	return PROTOCOL_INITIAL_SHARD_ORDER;
}

static inline u32 num_shards(const struct protocol_block_header *hdr)
{
	return 1 << hdr->shard_order;
}
#endif /* PETTYCOIN_SHARD_H */
