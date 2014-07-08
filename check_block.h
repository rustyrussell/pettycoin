#ifndef PETTYCOIN_CHECK_BLOCK_H
#define PETTYCOIN_CHECK_BLOCK_H
#include <stdbool.h>
#include <stddef.h>
#include <ccan/short_types/short_types.h>
#include "protocol_net.h"
#include "block_shard.h"

struct protocol_block_header;
struct protocol_block_tailer;
struct protocol_double_sha;
struct state;
struct block;
struct log;

struct protocol_block_header *unmarshal_block_header(void *buffer, size_t size);

/* Returns error if bad, otherwise *blockp is placed in chain.
   Not sufficient by itself: see check_block_prev_merkles! 
   sha is set if not NULL (even if error occurs).
*/
enum protocol_ecode
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
			    const struct block_shard *shard);

void put_shard_of_hashes_into_block(struct state *state,
				    struct block *block,
				    struct block_shard *shard);

/* May add complaint if it's out of order. */
void put_tx_in_block(struct state *state,
		     struct block *block,
		     struct block_shard *shard, u8 txoff,
		     const struct txptr_with_ref txp);

/* Check what we can, using block->prev->...'s shards. */
bool check_block_prev_merkles(struct state *state,
			      const struct block *block);

/* Various assertions about a block */
void check_block(struct state *state, const struct block *block);
#endif /* PETTYCOIN_CHECK_BLOCK_H */
