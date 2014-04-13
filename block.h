#ifndef PETTYCOIN_BLOCK_H
#define PETTYCOIN_BLOCK_H
#include "protocol.h"
#include "state.h"
#include <stdbool.h>
#include <ccan/list/list.h>
#include <openssl/bn.h>

/* Only transactions we've proven are in block go in here! */
struct transaction_batch {
	/* Where this batch starts (should be N << PETTYCOIN_BATCH_ORDER) */
	unsigned int trans_start;
	/* How many transactions do we have?  Faster than counting NULLs */
	unsigned int count;
	union protocol_transaction *t[1 << PETTYCOIN_BATCH_ORDER];
};

struct block {
	/* In state->block_depths[blocknum]. */
	struct list_node list;

	/* 0 == genesis block. */
	unsigned int blocknum;

	/* Am I on the main chain? */
	bool main_chain;

	/* Do we know all transactions for this and ancestors? */
	bool all_known;

	/* Total work to get to this block. */
	BIGNUM total_work;

	/* Our parent (in previous generation). */
	struct block *prev;

	/* The block itself: */
	const struct protocol_block_header *hdr;
	const struct protocol_double_sha *merkles;
	const u8 *prev_merkles;
	const struct protocol_block_tailer *tailer;

	/* Cache double SHA of block */
	struct protocol_double_sha sha;
	/* Transactions: may not be fully populated. */
	struct transaction_batch **batch;
};

/* Find on this chain. */
struct state;
struct block *block_find(struct block *start, const u8 lower_sha[4]);

/* Find anywhere. */
struct block *block_find_any(struct state *state,
			     const struct protocol_double_sha *sha);

/* Maximum amount in batch (1 >> PETTYCOIN_BATCH_ORDER) except for last */
u32 batch_max(const struct block *block, unsigned int batchnum);

/* Do we have everything in this batch? */
bool batch_full(const struct block *block, const struct transaction_batch *batch);

/* Do we have everything in this block? */
bool block_full(const struct block *block, unsigned int *batchnum);

/* Is this block in the main chain? */
bool block_in_main(const struct block *block);

static inline const struct block *genesis_block(const struct state *state)
{
	return list_top(state->block_depth[0], struct block, list);
}

/* Add this new block into the state structure: true if we changed top block. */
bool block_add(struct state *state, struct block *b);

static inline size_t batch_index(u32 trans_num)
{
	return trans_num >> PETTYCOIN_BATCH_ORDER;
}

/* Get this numbered transaction inside block. */
union protocol_transaction *block_get_trans(const struct block *block,
					    u32 trans_num);

#endif /* PETTYCOIN_BLOCK_H */
