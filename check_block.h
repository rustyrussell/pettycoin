#ifndef PETTYCOIN_CHECK_BLOCK_H
#define PETTYCOIN_CHECK_BLOCK_H
#include <stdbool.h>
#include <stddef.h>
#include <ccan/short_types/short_types.h>
#include "protocol_net.h"

struct protocol_block_header;
struct protocol_block_tailer;
struct protocol_double_sha;
struct transaction_batch;
struct state;
struct block;

struct protocol_block_header *unmarshall_block_header(void *buffer,
						      size_t size);

/* Returns error if bad, otherwise *blockp is placed in chain.
   Not sufficient by itself: see check_block_prev_merkles! */
enum protocol_error
check_block_header(struct state *state,
		   const struct protocol_block_header *hdr,
		   const struct protocol_double_sha *merkles,
		   const u8 *prev_merkles,
		   const struct protocol_block_tailer *tailer,
		   struct block **blockp);

/* Is this batch valid?  Can be called even if it's not full. */
bool check_batch_valid(struct state *state,
		       const struct block *block,
		       const struct transaction_batch *batch);

/* If this batch matches block, block steals batch. */
bool put_batch_in_block(struct state *state,
			struct block *block,
			struct transaction_batch *batch);

/* Check what we can, using block->prev->...'s batch. */
bool check_block_prev_merkles(struct state *state,
			      const struct block *block);

#endif /* PETTYCOIN_CHECK_BLOCK_H */
