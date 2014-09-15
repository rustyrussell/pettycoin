#include "block.h"
#include "chain.h"
#include "merkle_recurse.h"
#include "protocol.h"
#include "reward.h"
#include "shadouble.h"
#include "shard.h"
#include "tx.h"

static void get_shard_and_off(const struct block *b, u32 n,
			      u16 *shardnum, u8 *txoff)
{
	unsigned int i;

	for (i = 0; i < block_num_shards(&b->bi); i++) {
		if (n < block_num_txs(&b->bi, i)) {
			*shardnum = i;
			*txoff = n;
			return;
		}
		n -= block_num_txs(&b->bi, i);
	}
	abort();
}

static u32 num_txs(const struct block *b)
{
	unsigned int i;
	u32 total = 0;

	for (i = 0; i < block_num_shards(&b->bi); i++)
		total += block_num_txs(&b->bi, i);
	return i;
}

bool reward_get_tx(struct state *state,
		   const struct block *reward_block,
		   const struct block *claim_block,
		   u16 *shardnum, u8 *txoff)
{
	u32 reward_end, tx;
	const struct block *decider;
	struct protocol_double_sha sha;
	BIGNUM *val;

	if (block_empty(reward_block))
		return false;

	if (!block_preceeds(reward_block, claim_block))
		return false;

	/* Which block decides the reward?  End of reward period. */
	reward_end = (block_height(&reward_block->bi)
		      + PROTOCOL_REWARD_PERIOD - 1) / PROTOCOL_REWARD_PERIOD
		* PROTOCOL_REWARD_PERIOD;

	/* Not decided yet? */
	if (block_height(&claim_block->bi) <= reward_end)
		return false;

	/* Decider is reward_end on way to claim block. */
	decider = block_ancestor(claim_block,
				 block_height(&reward_block->bi)
				 - reward_end);

	/* Hash the two shas together. */
	merkle_two_hashes(&reward_block->sha.sha, &decider->sha.sha, &sha);

	val = BN_bin2bn(sha.sha, sizeof(sha.sha), NULL);
	assert(val);

	/* That selects which tx is the basis for the reward. */
	tx = BN_mod_word(val, num_txs(reward_block));

	get_shard_and_off(reward_block, tx, shardnum, txoff);
	BN_free(val);

	return true;
}

u32 reward_amount(const struct block *block, const union protocol_tx *tx)
{
	if (!tx_pays_fee(tx))
		return 0;

	return PROTOCOL_REWARD(tx_amount_for_fee(tx), num_txs(block));
}
