#include <ccan/structeq/structeq.h>
#include "proof.h"
#include "merkle_txs.h"
#include "block.h"
#include "shadouble.h"
#include "shard.h"
#include "merkle_recurse.h"
#include <assert.h>

void create_proof(struct protocol_proof *proof,
		  const struct block_shard *shard, u8 txoff)
{
	unsigned int i;

	/* If we have a canned proof, return that. */
	if (shard->proof && shard->proof[txoff]) {
		*proof = *shard->proof[txoff];
		return;
	}

	/* We only should get rid of shard->proofs once we can make our own. */
	assert(shard_all_hashes(shard));

	for (i = 0; i < 8; i++) {
		if (txoff & (1 << i))
			/* Hash the left side together. */
			merkle_some_txs(shard, 0, 1 << i, &proof->merkle[i]);
		else
			/* Hash the right side together */
			merkle_some_txs(shard, 1 << i, 1 << i,
					&proof->merkle[i]);
	}
}

/* What does proof say the merkle should be? */
static void proof_merkles_to(const union protocol_tx *tx,
			     const struct protocol_input_ref *refs,
			     u8 txoff,
			     const struct protocol_proof *proof,
			     struct protocol_double_sha *sha)
{
	unsigned int i;
	struct protocol_net_txrefhash txrefhash;

	/* Start with hash of transaction. */
	hash_tx_and_refs(tx, refs, &txrefhash);

	/* Combine them together. */
	merkle_two_hashes(&txrefhash.txhash, &txrefhash.refhash, sha);

	for (i = 0; i < 8; i++) {
		if (txoff & (1 << i)) {
			/* We're on the right. */
			merkle_two_hashes(&proof->merkle[i], sha, sha);
		} else {
			/* We're on the left. */
			merkle_two_hashes(sha, &proof->merkle[i], sha);
		}
	}
}

bool check_proof(const struct protocol_proof *proof,
		 const struct block *b,
		 u16 shardnum, u8 txoff,
		 const union protocol_tx *tx,
		 const struct protocol_input_ref *refs)
{
	struct protocol_double_sha merkle;

	/* Can't be right if shard doesn't exist. */
	if (shardnum >= (1 << b->hdr->shard_order))
		return false;

	/* Can't be the right one if not within shard */
	if (txoff >= b->shard_nums[shardnum])
		return false;

	proof_merkles_to(tx, refs, txoff, proof, &merkle);

	return structeq(&b->merkles[shardnum], &merkle);
}
