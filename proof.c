#include "proof.h"
#include "merkle_transactions.h"
#include "block.h"
#include "shadouble.h"
#include <assert.h>

void create_proof(struct protocol_proof *proof,
		  const struct block *block,
		  u32 tnum)
{
	unsigned int i;
	const union protocol_transaction **t;
	const struct protocol_input_ref **refs;

	proof->tnum = cpu_to_le32(tnum);

	assert(block_full(block, NULL));
	t = block->batch[batch_index(tnum)]->t;
	refs = block->batch[batch_index(tnum)]->refs;

	for (i = 0; i < PETTYCOIN_BATCH_ORDER; i++) {
		if (tnum & (1 << i))
			/* Hash the left side together. */
			merkle_transactions(NULL, 0, t, refs, 1 << i, 
					    &proof->merkle[i]);
		else
			merkle_transactions(NULL, 0, t + (1 << i),
					    refs + (1 << i), 1 << i, 
					    &proof->merkle[i]);
	}
}

/* What does proof say the merkle should be? */
static void proof_merkles_to(const union protocol_transaction *t,
			     const struct protocol_proof *proof,
			     struct protocol_double_sha *sha)
{
	unsigned int i;

	/* Start with hash of transaction. */
	hash_tx(t, sha);

	for (i = 0; i < PETTYCOIN_BATCH_ORDER; i++) {
		SHA256_CTX shactx;

		SHA256_Init(&shactx);
		if (le32_to_cpu(proof->tnum) & (1 << i)) {
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
		 const union protocol_transaction *t)
{
	struct protocol_double_sha merkle;
	u32 idx;

	proof_merkles_to(t, proof, &merkle);

	/* Can't be the right one if not within num transactions */
	if (le32_to_cpu(proof->tnum) >= le32_to_cpu(b->hdr->num_transactions))
		return false;

	idx = batch_index(le32_to_cpu(proof->tnum));
	return memcmp(b->merkles[idx].sha, merkle.sha, sizeof(merkle.sha)) == 0;
}
