#include "proof.h"
#include "merkle_transactions.h"
#include "block.h"
#include "shadouble.h"
#include "shard.h"
#include <assert.h>

void create_proof(struct protocol_proof *proof,
		  const struct block *block, u16 shardnum, u8 txoff)
{
	unsigned int i;
	const union protocol_transaction **t;
	const struct protocol_input_ref **refs;

	assert(shardnum < num_shards(block->hdr));
	assert(shard_full(block, shardnum));
	t = block->shard[shardnum]->t;
	refs = block->shard[shardnum]->refs;

	for (i = 0; i < 8; i++) {
		if (txoff & (1 << i))
			/* Hash the left side together. */
			merkle_transactions(NULL, 0, t, refs, 0, 1 << i,
					    &proof->merkle[i]);
		else
			merkle_transactions(NULL, 0, t, refs, 1 << i, 1 << i, 
					    &proof->merkle[i]);
	}
}

/* What does proof say the merkle should be? */
static void proof_merkles_to(const union protocol_transaction *t,
			     u8 txoff,
			     const struct protocol_proof *proof,
			     struct protocol_double_sha *sha)
{
	unsigned int i;

	/* Start with hash of transaction. */
	hash_tx(t, sha);

	for (i = 0; i < 8; i++) {
		SHA256_CTX shactx;

		SHA256_Init(&shactx);
		if (txoff & (1 << i)) {
			/* We're on the right. */
			SHA256_Update(&shactx, &proof->merkle[i],
				      sizeof(proof->merkle[i]));
			SHA256_Update(&shactx, sha->sha, sizeof(sha->sha));
		} else {
			/* We're on the left. */
			SHA256_Update(&shactx, sha->sha, sizeof(sha->sha));
			SHA256_Update(&shactx, &proof->merkle[i],
				      sizeof(proof->merkle[i]));
		}
		SHA256_Double_Final(&shactx, sha);
	}
}

bool check_proof(const struct protocol_proof *proof,
		 const struct block *b,
		 const union protocol_transaction *t,
		 u16 shardnum, u8 txoff)
{
	struct protocol_double_sha merkle;

	/* Can't be right if shard doesn't exist. */
	if (shardnum >= (1 << b->hdr->shard_order))
		return false;

	/* Can't be the right one if not within shard */
	if (txoff >= b->shard_nums[shardnum])
		return false;

	proof_merkles_to(t, txoff, proof, &merkle);

	return memcmp(b->merkles[shardnum].sha, merkle.sha, sizeof(merkle.sha))
		== 0;
}
