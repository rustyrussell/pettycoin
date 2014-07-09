#ifndef PETTYCOIN_BLOCK_H
#define PETTYCOIN_BLOCK_H
#include "config.h"
#include "block_shard.h"
#include "protocol.h"
#include "protocol_net.h"
#include "state.h"
#include <ccan/bitmap/bitmap.h>
#include <ccan/cast/cast.h>
#include <ccan/list/list.h>
#include <openssl/bn.h>
#include <stdbool.h>

struct block {
	/* In state->block_depths[le32_to_cpu(hdr->depth)]. */
	struct list_node list;

	/* Links through sibling. */
	struct list_head children;

	/* In prev->children list. */
	struct list_node sibling;

	/* What features have been locked in for next fortnight? */
	u8 pending_features;

	/* Do we know all transactions for this and ancestors? */
	bool all_known;

	/* Total work to get to this block. */
	BIGNUM total_work;

	/* Our parent (in previous generation). */
	struct block *prev;

	/* The block itself: */
	const struct protocol_block_header *hdr;
	const u8 *shard_nums;
	const struct protocol_double_sha *merkles;
	const u8 *prev_txhashes;
	const struct protocol_block_tailer *tailer;

	/* This is set if there's a problem with the block (or ancestor). */
	const void *complaint;

	/* Cache double SHA of block */
	struct protocol_double_sha sha;
	/* Transactions: may not be fully populated. */
	struct block_shard **shard;
};

/* Find on this chain. */
struct state;
struct block *block_find(struct block *start, const u8 lower_sha[4]);

/* Find anywhere. */
struct block *block_find_any(struct state *state,
			     const struct protocol_double_sha *sha);

/* Do we have every tx in this block? */
bool block_all_known(const struct block *block);

static inline const struct block *genesis_block(const struct state *state)
{
	return list_top(state->block_depth[0], struct block, list);
}

/* Create a new block and add into the state structure. */
struct block *block_add(struct state *state,
			struct block *prev,
			const struct protocol_double_sha *sha,
			const struct protocol_block_header *hdr,
			const u8 *shard_nums,
			const struct protocol_double_sha *merkles,
			const u8 *prev_txhashes,
			const struct protocol_block_tailer *tailer);

/* Get tx_idx'th tx inside shard shardnum inside block. */
union protocol_tx *block_get_tx(const struct block *block, u16 shardnum,
				u8 txoff);

/* Get this numbered references inside block. */
struct protocol_input_ref *block_get_refs(const struct block *block,
					  u16 shardnum, u8 txoff);
#endif /* PETTYCOIN_BLOCK_H */
