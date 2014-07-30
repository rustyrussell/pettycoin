#ifndef PETTYCOIN_CHECK_BLOCK_H
#define PETTYCOIN_CHECK_BLOCK_H
#include "config.h"
#include "block_shard.h"
#include "protocol_net.h"
#include <ccan/short_types/short_types.h>
#include <stdbool.h>
#include <stddef.h>

struct protocol_block_header;
struct protocol_block_tailer;
struct protocol_double_sha;
struct protocol_proof;
struct state;
struct block;
struct log;

struct protocol_block_header *unmarshal_block_header(void *buffer, size_t size);

/* Returns error if bad.  You should also call check_block_prev_txhashes! */
enum protocol_ecode
check_block_header(struct state *state,
		   const struct protocol_block_header *hdr,
		   const u8 *shard_nums,
		   const struct protocol_double_sha *merkles,
		   const u8 *prev_txhashes,
		   const struct protocol_block_tailer *tailer,
		   struct block **blockp,
		   struct protocol_double_sha *sha);

/* Does merkle match? */
bool shard_belongs_in_block(const struct block *block,
			    const struct block_shard *shard);

/* If we put tx in shard at txoff, will it be in order?  If not, give
 * offset of conflicting tx in bad_txoff */
bool check_tx_ordering(struct state *state,
		       struct block *block,
		       struct block_shard *shard, u8 txoff,
		       const union protocol_tx *tx,
		       u8 *bad_txoff);

/* You normally call check_tx_ordering first! */
void put_tx_in_shard(struct state *state,
		     const struct peer *source,
		     struct block *block,
		     struct block_shard *shard, u8 txoff,
		     const struct txptr_with_ref txp);

bool put_txhash_in_shard(struct state *state,
			 struct block *block, u16 shardnum, u8 txoff,
			 const struct protocol_txrefhash *txrefhash);

/* After you've put in tx, you put in proof. */
void put_proof_in_shard(struct state *state,
			struct block *block,
			const struct protocol_proof *proof);

bool check_num_prev_txhashes(struct state *state,
			     const struct block *prev_block,
			     const struct protocol_block_header *hdr,
			     const u8 *prev_txhashes);

/* Check what we can, using block->prev etc's shards. */
bool check_prev_txhashes(struct state *state, const struct block *block,
			 const struct block **bad_prev,
			 u16 *bad_shard);

/* Check both inputs and references for this transaction. */
bool check_tx_inputs_and_refs(struct state *state,
			      struct block *block,
			      const struct protocol_proof *proof,
			      union protocol_tx *tx,
			      struct protocol_input_ref *refs);

/* Various assertions about a block */
void check_block(struct state *state, const struct block *block, bool all);
#endif /* PETTYCOIN_CHECK_BLOCK_H */
