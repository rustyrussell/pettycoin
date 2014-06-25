#ifndef PETTYCOIN_HASH_BLOCK_H
#define PETTYCOIN_HASH_BLOCK_H
#include "protocol.h"

void hash_block(const struct protocol_block_header *hdr,
		const u8 *shard_nums,
		const struct protocol_double_sha *merkles,
		const u8 *prev_merkles,
		const struct protocol_block_tailer *tailer,
		struct protocol_double_sha *sha);

#endif /* PETTYCOIN_HASH_BLOCK_H */
