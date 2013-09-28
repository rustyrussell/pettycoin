#include "state.h"
#include "create_proof.h"
#include "block.h"
#include "merkle_transactions.h"
#include <ccan/tal/tal.h>
#include <ccan/cast/cast.h>

static void add_proof(struct protocol_proof **arr,
		      const struct protocol_proof *proof)
{
	size_t n = tal_count(*arr);

	tal_resize(arr, n + 1);
	(*arr)[n] = *proof;
}

static void add_transaction(union protocol_transaction ***arr,
			    union protocol_transaction *trans)
{
	size_t n = tal_count(*arr);

	tal_resize(arr, n + 1);
	(*arr)[n] = trans;
}

static struct protocol_proof *mkproof(const tal_t *ctx,
				      struct block *block,
				      u32 num)
{
	unsigned int i;
	union protocol_transaction **t;
	struct protocol_proof *proof = tal(ctx, struct protocol_proof);

	memcpy(proof->blocksig, block->sha.sha, sizeof(proof->blocksig));
	proof->num = cpu_to_le32(num);

	t = block->batch[batch_index(num)]->t;

	for (i = 0; i < PETTYCOIN_BATCH_ORDER; i++) {
		if (num & (1 << i))
			/* Hash the left side together. */
			merkle_transactions(NULL, 0, t, 1 << i, 
					    &proof->merkle[i]);
		else
			merkle_transactions(NULL, 0, t + (1 << i), 1 << i, 
					    &proof->merkle[i]);
	}
	return proof;
}

static void add_inputs(struct state *state,
		       struct protocol_proof **proofs,
		       union protocol_transaction ***transarr,
		       const union protocol_transaction *t)
{
	u32 i;

	switch (t->hdr.type) {
	case TRANSACTION_NORMAL:
		for (i = 0; i < le16_to_cpu(t->normal.num_inputs); i++) {
			union protocol_transaction *subt;
			struct thash_elem *e;

			e = thash_get(&state->thash,
				      &t->normal.input[i].input);
			assert(e);
			subt = block_get_trans(e->block, e->tnum);
			assert(subt);

			add_transaction(transarr, subt);
			add_proof(proofs, mkproof(*proofs, e->block, e->tnum));
			add_inputs(state, proofs, transarr, subt); 
		}
		break;
	case TRANSACTION_FROM_GATEWAY:
		break;
	default:
		abort();
	}
}

struct protocol_proof *create_proof(struct state *state,
				    const union protocol_transaction *trans,
				    union protocol_transaction ***transarr)
{
	struct protocol_proof *proofs;

	proofs = tal_arr(state, struct protocol_proof, 0);

	/* First transactions is the one we are using. */
	*transarr = tal_arr(state, union protocol_transaction *, 1);
	(*transarr)[0] = cast_const(union protocol_transaction *, trans);

	add_inputs(state, &proofs, transarr, trans);

	return proofs;
}
