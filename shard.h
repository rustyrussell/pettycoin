#ifndef PETTYCOIN_SHARD_H
#define PETTYCOIN_SHARD_H
#include "protocol.h"

static inline u32 shard_of(const struct protocol_address *addr, u32 num_shards)
{
	be32 shard;

	memcpy(&shard, addr->addr, sizeof(shard));
	return be32_to_cpu(shard) & (num_shards - 1);
}

struct block;

/* FIXME: voting mechanism to double num_shards. */
static inline u32 num_shards(const struct block *block)
{
	return PROTOCOL_INITIAL_SHARDS;
}
#endif /* PETTYCOIN_SHARD_H */
