#ifndef PETTYCOIN_BLOCK_H
#define PETTYCOIN_BLOCK_H
#include "protocol.h"
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
	/* Chained into state.blocks if in main chain, NULL otherwise. */
	struct list_node list;

	/* Total work to get to this block. */
	BIGNUM total_work;

	/* 0 == genesis block. */
	unsigned int blocknum;
	/* Ring of peers: have same blocknum. */
	struct block *peers;
	/* Our parent. */
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

/* Do we have everything in this batch? */
bool batch_full(const struct block *block,
		const struct transaction_batch *batch);

/* Is this block in the main chain? */
bool block_in_main(const struct block *block);

static inline size_t batch_index(u32 trans_num)
{
	return trans_num >> PETTYCOIN_BATCH_ORDER;
}

/* Get this numbered transaction inside block. */
union protocol_transaction *block_get_trans(const struct block *block,
					    u32 trans_num);

/* Add this (verified OK) block to the state. */
void add_block(struct state *state, struct block *block);

#endif /* PETTYCOIN_BLOCK_H */
