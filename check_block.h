#ifndef PETTYCOIN_CHECK_BLOCK_H
#define PETTYCOIN_CHECK_BLOCK_H
#include <stdbool.h>
#include <stddef.h>
#include <ccan/short_types/short_types.h>
#include "protocol_net.h"

struct protocol_block_header;
struct protocol_block_tailer;
struct protocol_double_sha;
struct transaction_shard;
struct state;
struct block;
struct log;

struct protocol_block_header *unmarshall_block_header(void *buffer,
						      size_t size);

/* Returns error if bad, otherwise *blockp is placed in chain.
   Not sufficient by itself: see check_block_prev_merkles! 
   sha is set if not NULL (even if error occurs).
*/
enum protocol_error
check_block_header(struct state *state,
		   const struct protocol_block_header *hdr,
		   const u8 *shard_nums,
		   const struct protocol_double_sha *merkles,
		   const u8 *prev_merkles,
		   const struct protocol_block_tailer *tailer,
		   struct block **blockp,
		   struct protocol_double_sha *sha);

/* Does merkle match? */
bool shard_belongs_in_block(const struct block *block,
			    const struct transaction_shard *shard);

/* Is this shard ordering valid?  Can be called even if it's not full. */
bool check_tx_order(struct state *state,
		    const struct block *block,
		    const struct transaction_shard *shard,
		    unsigned int *bad_transnum1,
		    unsigned int *bad_transnum2);

/* Are all the transactions valid? */
enum protocol_error
shard_validate_transactions(struct state *state,
			    struct log *log,
			    const struct block *block,
			    struct transaction_shard *shard,
			    unsigned int *bad_trans,
			    unsigned int *bad_input_num,
			    union protocol_transaction **bad_input);

/* For generating.c: inserts a fully-populated shard. */
void force_shard_into_block(struct state *state,
			    struct block *block,
			    struct transaction_shard *shard);

/* Check what we can, using block->prev->...'s shards. */
bool check_block_prev_merkles(struct state *state,
			      const struct block *block);

#endif /* PETTYCOIN_CHECK_BLOCK_H */
