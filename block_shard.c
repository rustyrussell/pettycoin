#include "block.h"
#include "block_shard.h"
#include "check_tx.h"
#include "merkle_txs.h"
#include "proof.h"
#include "shard.h"
#include "tx.h"
#include <assert.h>
#include <ccan/structeq/structeq.h>

/* For compactness, struct block_shard needs tx and refs adjacent. */
struct txptr_with_ref txptr_with_ref(const tal_t *ctx,
				     const union protocol_tx *tx,
				     const struct protocol_input_ref *refs)
{
	struct txptr_with_ref txp;
	size_t txlen, reflen;
	char *p;

	txlen = marshal_tx_len(tx);
	reflen = num_inputs(tx) * sizeof(struct protocol_input_ref);

	p = tal_alloc_(ctx, txlen + reflen, false, "txptr_with_ref");
	memcpy(p, tx, txlen);
	memcpy(p + txlen, refs, reflen);

	txp.tx = (union protocol_tx *)p;
	return txp;
}

struct block_shard *new_block_shard(const tal_t *ctx, u16 shardnum, u8 num)
{
	struct block_shard *s;

	s = tal_alloc_(ctx,
		       offsetof(struct block_shard, u[num]),
		       true, "struct block_shard");
	s->shardnum = shardnum;
	s->size = num;
	return s;
}

/* If we have the tx, hash it, otherwise return hash. */
const struct protocol_net_txrefhash *
txrefhash_in_shard(const struct block_shard *s,
		   u8 txoff,
		   struct protocol_net_txrefhash *scratch)
{
	assert(txoff < s->size);
	
	if (shard_is_tx(s, txoff)) {
		const union protocol_tx *tx = tx_for(s, txoff);
		if (!tx)
			return NULL;
		hash_tx_and_refs(tx, refs_for(s->u[txoff].txp), scratch);
		return scratch;
	} else
		return s->u[txoff].hash;
}

bool shard_all_known(const struct block_shard *shard)
{
	return shard->txcount == shard->size;
}	

/* Do we have every tx or hash? */
bool shard_all_hashes(const struct block_shard *shard)
{
	return shard->txcount + shard->hashcount == shard->size;
}

void check_block_shard(struct state *state,
		       const struct block *block,
		       const struct block_shard *shard)
{
	unsigned int i, txcount = 0, hashcount = 0;

	assert(shard->size == block->shard_nums[shard->shardnum]);

	if (shard_all_hashes(shard))
		assert(!shard->proof);
	else if (shard->txcount != 0)
		assert(shard->proof);

	for (i = 0; i < shard->size; i++) {
		if (shard_is_tx(shard, i)) {
			if (shard->u[i].txp.tx) {
				unsigned int bad;
				assert(check_tx(state, shard->u[i].txp.tx,
						block)
				       == PROTOCOL_ECODE_NONE);
				/* We don't put TXs in with unknown inputs. */
				assert(check_tx_inputs(state,
						       shard->u[i].txp.tx,
						       &bad)
				       == ECODE_INPUT_OK);
				if (shard->proof)
					assert(check_proof(shard->proof[i],
							   block,
							   shard->shardnum, i,
							   shard->u[i].txp.tx,
							   refs_for(shard->u[i]
								    .txp)));
				txcount++;
			}
		} else {
			assert(shard->u[i].hash);
			hashcount++;
		}
	}
	assert(txcount == shard->txcount);
	assert(hashcount == shard->hashcount);

	assert(txcount + hashcount <= shard->size);
	if (txcount + hashcount == shard->size) {
		struct protocol_double_sha sha;
		merkle_txs(shard, &sha);
		assert(structeq(&sha, &block->merkles[shard->shardnum]));
	}
}

bool interested_in_shard(const struct state *state,
			 unsigned int shard_order, u16 shard)
{
	unsigned int ord_diff;

	/* Convert block's shard number to our interest number. */
	ord_diff = shard_order - PROTOCOL_INITIAL_SHARD_ORDER;

	return bitmap_test_bit(state->interests, shard >> ord_diff);
}
