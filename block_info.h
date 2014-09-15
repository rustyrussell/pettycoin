#ifndef PETTYCOIN_BLOCK_INFO_H
#define PETTYCOIN_BLOCK_INFO_H
#include "config.h"
#include "prev_blocks.h"
#include "protocol.h"
#include "shard.h"
#include <assert.h>

/* Describes the internal structure of a block on the wire. */
struct block_info {
	/* The pettycoin part: */
	const struct protocol_block_header *hdr;
	/* There are num_prevs(hdr) protocoL_block_id: */
	const struct protocol_block_id *prevs;
	/* There are num_shards(hdr) u8: */
	const u8 *num_txs;
	/* There are num_shards(hdr) protocol_double_sha: */
	const struct protocol_double_sha *merkles;
	/* There are le32_to_cpu(hdr->num_prev_txhashes) u8: */
	const u8 *prev_txhashes;
	/* The tailer: */
	const struct protocol_block_tailer *tailer;
};

static inline u32 block_timestamp(const struct block_info *blocki)
{
	return le32_to_cpu(blocki->tailer->timestamp);
}

static inline u32 block_difficulty(const struct block_info *blocki)
{
	return le32_to_cpu(blocki->tailer->difficulty);
}

static inline u32 block_height(const struct block_info *blocki)
{
	return le32_to_cpu(blocki->hdr->height);
}

static inline u32 block_num_shards(const struct block_info *blocki)
{
	return num_shards(blocki->hdr);
}

static inline u32 block_num_prevs(const struct block_info *blocki)
{
	return num_prevs(blocki->hdr);
}

static inline const struct protocol_block_id *
block_prev(const struct block_info *blocki, u32 i)
{
	return blocki->hdr->prevs + i;
}

static inline const struct protocol_double_sha *
block_merkle(const struct block_info *blocki, u32 shard)
{
	assert(shard < block_num_shards(blocki));
	return blocki->merkles + shard;
}

static inline const u8 block_num_txs(const struct block_info *blocki, u32 shard)
{
	assert(shard < block_num_shards(blocki));
	return blocki->num_txs[shard];
}
#endif /* PETTYCOIN_BLOCK_INFO_H */
