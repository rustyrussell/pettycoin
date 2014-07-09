#include "block.h"
#include "merkle_recurse.h"
#include "merkle_txs.h"
#include "proof.h"
#include "shadouble.h"
#include "shard.h"
#include <assert.h>
#include <ccan/structeq/structeq.h>

void create_proof(struct protocol_proof *proof,
		  const struct block *block, u16 shardnum, u8 txoff)
{
	unsigned int i;
	const struct block_shard *shard = block->shard[shardnum];

	/* If we have a canned proof, return that. */
	if (shard->proof && shard->proof[txoff]) {
		*proof = *shard->proof[txoff];
		return;
	}

	proof->pos.block = block->sha;
	proof->pos.shard = cpu_to_le16(shardnum);
	proof->pos.txoff = txoff;
	proof->pos.unused = 0;

	/* We only should get rid of shard->proofs once we can make our own. */
	assert(shard_all_hashes(shard));

	for (i = 0; i < 8; i++) {
		if (txoff & (1 << i))
			/* Hash the left side together. */
			merkle_some_txs(shard, 0, 1 << i,
					&proof->merkles.merkle[i]);
		else
			/* Hash the right side together */
			merkle_some_txs(shard, 1 << i, 1 << i,
					&proof->merkles.merkle[i]);
	}
}

/* What does proof say the merkle should be? */
static void proof_merkles_to(const struct protocol_net_txrefhash *txrefhash,
			     const struct protocol_proof *proof,
			     struct protocol_double_sha *sha)
{
	unsigned int i;

	/* Combine them together. */
	merkle_two_hashes(&txrefhash->txhash, &txrefhash->refhash, sha);

	for (i = 0; i < 8; i++) {
		if (proof->pos.txoff & (1 << i)) {
			/* We're on the right. */
			merkle_two_hashes(&proof->merkles.merkle[i], sha, sha);
		} else {
			/* We're on the left. */
			merkle_two_hashes(sha, &proof->merkles.merkle[i], sha);
		}
	}
}

bool check_proof_byhash(const struct protocol_proof *proof,
			const struct block *b,
			const struct protocol_net_txrefhash *txrefhash)
{
	struct protocol_double_sha merkle;
	u16 shardnum = le16_to_cpu(proof->pos.shard);

	assert(structeq(&b->sha, &proof->pos.block));

	/* Can't be right if shard doesn't exist. */
	if (shardnum >= (1 << b->hdr->shard_order))
		return false;

	/* Can't be the right one if not within shard */
	if (proof->pos.txoff >= b->shard_nums[shardnum])
		return false;

	proof_merkles_to(txrefhash, proof, &merkle);

	return structeq(&b->merkles[shardnum], &merkle);
}

bool check_proof(const struct protocol_proof *proof,
		 const struct block *b,
		 const union protocol_tx *tx,
		 const struct protocol_input_ref *refs)
{
	struct protocol_net_txrefhash txrefhash;

	/* Start with hash of transaction. */
	hash_tx_and_refs(tx, refs, &txrefhash);

	return check_proof_byhash(proof, b, &txrefhash);
}
