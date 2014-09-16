#include "block.h"
#include "chain.h"
#include "state.h"
#include "tx_in_hashes.h"

void add_txhash_to_hashes(struct state *state,
			  const tal_t *ctx,
			  struct block *block, u16 shard, u8 txoff,
			  const struct protocol_tx_id *txhash)
{
	union txhash_block_or_tx u;

	u.block = block;
	txhash_add_tx(&state->txhash, ctx, u, shard, txoff, TX_IN_BLOCK,
		      txhash);
}

void add_tx_to_hashes(struct state *state,
		      const tal_t *ctx,
		      struct block *block, u16 shard, u8 txoff,
		      const union protocol_tx *tx)
{
	struct protocol_tx_id txhash;

	hash_tx(tx, &txhash);

	/* First time we heard of full transaction?  Add inputs. */
	if (!txhash_gettx(&state->txhash, &txhash, TX_PENDING))
		inputhash_add_tx(state, &state->inputhash, tx);

	add_txhash_to_hashes(state, ctx, block, shard, txoff, &txhash);
}

void remove_tx_from_hashes(struct state *state,
			   struct block *block, u16 shard, u8 txoff)
{
	struct protocol_tx_id scratch;
	const struct protocol_tx_id *txhash;
	const union protocol_tx *tx;
	union txhash_block_or_tx u;

	u.block = block;

	if (shard_is_tx(block->shard[shard], txoff)) {
		tx = tx_for(block->shard[shard], txoff);
		hash_tx(tx, &scratch);
		txhash = &scratch;
	} else {
		txhash = &block->shard[shard]->u[txoff].hash->txhash;
		tx = NULL;
	}

	txhash_del_tx(&state->txhash, u, shard, txoff, TX_IN_BLOCK, txhash);

	/* If this tx is no longer known at *all*, we can remove from
	 * input hash too. */
	if (tx && !txhash_gettx(&state->txhash, txhash, TX_PENDING))
		inputhash_del_tx(&state->inputhash, tx);
}

/* This is called *before* we turn txrefhash into tx pointer, so
 * txhash_gettx won't return this entry. */
void upgrade_tx_in_hashes(struct state *state,
			  const struct protocol_tx_id *sha,
			  const union protocol_tx *tx)
{
	/* If we didn't know about full tx before, add inputs to hash. */
	if (!txhash_gettx(&state->txhash, sha, TX_PENDING))
		inputhash_add_tx(state, &state->inputhash, tx);
}

void add_pending_tx_to_hashes(struct state *state,
			      const tal_t *ctx,
			      const union protocol_tx *tx)
{
	struct protocol_tx_id txhash;
	union txhash_block_or_tx u;

	hash_tx(tx, &txhash);

	assert(!txhash_get_pending_tx(state, &txhash));

	/* First time we heard of full transaction?  Add inputs. */
	if (!txhash_gettx(&state->txhash, &txhash, TX_PENDING))
		inputhash_add_tx(state, &state->inputhash, tx);

	u.tx = tx;
	txhash_add_tx(&state->txhash, ctx, u, 0, 0, TX_PENDING, &txhash);
}

void remove_pending_tx_from_hashes(struct state *state,
				   const union protocol_tx *tx)
{
	struct protocol_tx_id txhash;
	union txhash_block_or_tx u;

	hash_tx(tx, &txhash);
	u.tx = tx;
	txhash_del_tx(&state->txhash, u, 0, 0, TX_PENDING, &txhash);

	/* If this tx is no longer known at *all*, we can remove from
	 * input hash too. */
	if (!txhash_gettx(&state->txhash, &txhash, TX_PENDING))
		inputhash_del_tx(&state->inputhash, tx);
}

struct txhash_elem *txhash_gettx_ancestor(struct state *state,
					  const struct protocol_tx_id *sha,
					  const struct block *block)

{
	struct txhash_iter iter;
	struct txhash_elem *te;

	for (te = txhash_firstval(&state->txhash, sha, &iter);
	     te;
	     te = txhash_nextval(&state->txhash, sha, &iter)) {
		if (te->status != TX_IN_BLOCK)
			continue;

		if (block_preceeds(te->u.block, block))
			break;
	}
	return te;
}

const union protocol_tx *
txhash_get_pending_tx(struct state *state,
		      const struct protocol_tx_id *sha)
{
	struct txhash_iter iter;
	struct txhash_elem *te;

	for (te = txhash_firstval(&state->txhash, sha, &iter);
	     te;
	     te = txhash_nextval(&state->txhash, sha, &iter)) {
		if (te->status == TX_PENDING)
			return te->u.tx;
	}
	return NULL;
}

const union protocol_tx *txhash_tx(const struct txhash_elem *te)
{
	switch ((enum tx_status)te->status) {
	case TX_IN_BLOCK:
		return tx_for(te->u.block->shard[te->shardnum], te->txoff);
	case TX_PENDING:
		return te->u.tx;
	}
	abort();
}
