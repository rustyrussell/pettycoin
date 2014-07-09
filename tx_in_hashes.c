#include "block.h"
#include "chain.h"
#include "state.h"
#include "tx_in_hashes.h"

void add_txhash_to_hashes(struct state *state,
			  const tal_t *ctx,
			  struct block *block, u16 shard, u8 txoff,
			  const struct protocol_double_sha *txhash)
{
	txhash_add_tx(&state->txhash, ctx, block, shard, txoff, txhash);
}

void add_tx_to_hashes(struct state *state,
		      const tal_t *ctx,
		      struct block *block, u16 shard, u8 txoff,
		      const union protocol_tx *tx)
{
	struct protocol_double_sha txhash;

	hash_tx(tx, &txhash);

	/* First time we heard of full transaction?  Add inputs. */
	if (!txhash_gettx(&state->txhash, &txhash))
		inputhash_add_tx(&state->inputhash, ctx, tx);

	add_txhash_to_hashes(state, ctx, block, shard, txoff, &txhash);
}

void remove_tx_from_hashes(struct state *state,
			   struct block *block, u16 shard, u8 txoff)
{
	struct protocol_double_sha scratch;
	const struct protocol_double_sha *txhash;
	const union protocol_tx *tx;

	if (shard_is_tx(block->shard[shard], txoff)) {
		tx = tx_for(block->shard[shard], txoff);
		hash_tx(tx, &scratch);
		txhash = &scratch;
	} else {
		txhash = &block->shard[shard]->u[txoff].hash->txhash;
		tx = NULL;
	}

	txhash_del_tx(&state->txhash, block, shard, txoff, txhash);

	/* If this tx is no longer known at *all*, we can remove from
	 * input hash too. */
	if (tx && !txhash_gettx(&state->txhash, txhash))
		inputhash_del_tx(&state->inputhash, tx);
}

/* This is called *before* we turn txrefhash into tx pointer, so
 * txhash_gettx won't return this entry. */
void upgrade_tx_in_hashes(struct state *state,
			  const tal_t *ctx,
			  const struct protocol_double_sha *sha,
			  const union protocol_tx *tx)
{
	/* If we didn't know about full tx before, add inputs to hash. */
	if (!txhash_gettx(&state->txhash, sha))
		inputhash_add_tx(&state->inputhash, ctx, tx);
}

struct txhash_elem *txhash_gettx_ancestor(struct state *state,
					  const struct protocol_double_sha *sha,
					  const struct block *block)

{
	struct txhash_iter iter;
	struct txhash_elem *te;

	for (te = txhash_firstval(&state->txhash, sha, &iter);
	     te;
	     te = txhash_nextval(&state->txhash, sha, &iter)) {
		if (block_preceeds(te->block, block))
			break;
	}
	return te;
}
