#include "check_transaction.h"
#include "block.h"
#include "chain.h"
#include "gateways.h"
#include "hash_transaction.h"
#include "overflows.h"
#include "protocol.h"
#include "addr.h"
#include "shadouble.h"
#include "signature.h"
#include "state.h"
#include "shard.h"
#include "version.h"
#include <assert.h>
#include <ccan/endian/endian.h>
#include <ccan/tal/tal.h>

/* Check signature. */
enum protocol_error
check_trans_normal_basic(struct state *state,
			 const struct protocol_transaction_normal *t)
{
	if (!version_ok(t->version))
		return PROTOCOL_ERROR_HIGH_VERSION;

	if (le32_to_cpu(t->send_amount) > MAX_SATOSHI)
		return PROTOCOL_ERROR_TOO_LARGE;

	if (le32_to_cpu(t->change_amount) > MAX_SATOSHI)
		return PROTOCOL_ERROR_TOO_LARGE;

	if (le32_to_cpu(t->num_inputs) > TRANSACTION_MAX_INPUTS)
		return PROTOCOL_ERROR_TOO_MANY_INPUTS;

	if (le32_to_cpu(t->num_inputs) == 0)
		return PROTOCOL_ERROR_TOO_MANY_INPUTS;

	if (!check_trans_sign((const union protocol_transaction *)t,
			      &t->input_key, &t->signature))
		return PROTOCOL_ERROR_TRANS_BAD_SIG;

	return PROTOCOL_ERROR_NONE;
}

/* We failed to find it in hash. */
static enum protocol_error
find_trans_for_ref(struct state *state,
		   const struct block *block,
		   const struct protocol_input_ref *ref,
		   union protocol_transaction **trans)
{
	u32 bnum;
	const struct block *b;

	*trans = NULL;
	if (le32_to_cpu(ref->blocks_ago) > block->blocknum)
		return PROTOCOL_ERROR_PRIV_BATCH_BAD_INPUT_REF;

	/* FIXME: slow */
	bnum = block->blocknum - le32_to_cpu(ref->blocks_ago);
	for (b = block; b->blocknum != bnum; b = b->prev);

	if (le32_to_cpu(ref->txnum) >= le32_to_cpu(b->hdr->num_transactions))
		return PROTOCOL_ERROR_PRIV_BATCH_BAD_INPUT_REF;

	if (le32_to_cpu(b->tailer->timestamp) + TRANSACTION_HORIZON_SECS
	    < le32_to_cpu(block->tailer->timestamp))
		return PROTOCOL_ERROR_PRIV_BATCH_BAD_INPUT_REF;

	*trans = block_get_trans(b, le32_to_cpu(ref->txnum));
	if (!*trans)
		/* We just don't know it.  OK */
		return PROTOCOL_ERROR_NONE;

	/* Trans is actually not the correct one! */
	return PROTOCOL_ERROR_PRIV_BATCH_BAD_INPUT_REF_TRANS;
}	

/*
 * Sets inputs[] if transaction has inputs.
 * Sets bad_input_num if PROTOCOL_ERROR_PRIV_TRANS_BAD_INPUT.
 * If refs is non-NULL, ensures that Nth input tx matches ref[N].
 *
 * Otherwise bad_input_num indicates an unknown input.
 *
 * FIXME: Detect double-spends!
 */
static enum protocol_error
check_trans_normal_inputs(struct state *state,
			  const struct protocol_transaction_normal *t,
			  const struct block *block,
			  const struct protocol_input_ref *refs,
			  unsigned int *inputs_known,
			  union protocol_transaction *
			  inputs[TRANSACTION_MAX_INPUTS],
			  unsigned int *bad_input_num)
{
	unsigned int i, num;
	u64 input_total = 0;
	struct protocol_address my_addr;

	/* Get the input address used by this transaction. */
	pubkey_to_addr(&t->input_key, &my_addr);

	num = le32_to_cpu(t->num_inputs);
	*inputs_known = 0;

	for (i = 0; i < num; i++) {
		u32 amount;
		struct protocol_address addr;
		struct thash_iter it;
		struct thash_elem *te;

		for (te = thash_firstval(&state->thash,
					 &t->input[i].input, &it);
		     te;
		     te = thash_nextval(&state->thash,
					&t->input[i].input, &it)) {
			inputs[i] = block_get_trans(te->block, te->tnum);

			/* Not checking in block?  Any location will do. */
			if (!refs)
				break;

			/* Can't be right if block number wrong. */
			if (le32_to_cpu(te->block->blocknum)
			    != block->blocknum
			    - le32_to_cpu(refs[i].blocks_ago))
				continue;

			/* Can't be right if transaction number impossible. */
			if (le32_to_cpu(refs[i].txnum)
			    >= le32_to_cpu(te->block->hdr->num_transactions))
				continue;

			/* Must be predecessor */
			if (!block_preceeds(te->block, block))
				continue;

			break;
		}

		/* Unknown transaction? */
		if (!te) {
			inputs[i] = NULL;
			*bad_input_num = i;
			if (refs) {
				enum protocol_error err;
				/* Do we know what was input_ref referred to? */
				err = find_trans_for_ref(state, block, &refs[i],
							 &inputs[i]);
				if (err)
					return err;
			}
			/* Partial knowledge... */
			continue;
		}

		(*inputs_known)++;

		if (!find_output(inputs[i], le16_to_cpu(t->input[i].output),
				 &addr, &amount)) {
			*bad_input_num = i;
			return PROTOCOL_ERROR_PRIV_TRANS_BAD_INPUT;
		}

		/* Check it was to this address. */
		if (memcmp(&my_addr, &addr, sizeof(addr)) != 0) {
			*bad_input_num = i;
			log_debug(state->log, "Address mismatch against output %i of ", le16_to_cpu(t->input[i].output));
			log_add_struct(state->log, union protocol_transaction,
				       inputs[i]);
			return PROTOCOL_ERROR_PRIV_TRANS_BAD_INPUT;
		}

		input_total += amount;
	}

	if (*inputs_known == num) {
		if (input_total != (le32_to_cpu(t->send_amount)
				    + le32_to_cpu(t->change_amount))) {
			return PROTOCOL_ERROR_PRIV_TRANS_BAD_AMOUNTS;
		}
	}
	return PROTOCOL_ERROR_NONE;
}

/* block is NULL if we're not in a block (ie. pending tx) */
enum protocol_error
check_trans_from_gateway(struct state *state,
			 const struct block *block,
			 const struct protocol_transaction_gateway *t)
{
	u32 i;
	u32 shards, the_shard;

	if (!version_ok(t->version))
		return PROTOCOL_ERROR_TRANS_HIGH_VERSION;

	if (!accept_gateway(state, &t->gateway_key))
		return PROTOCOL_ERROR_TRANS_BAD_GATEWAY;

	/* Each output must be in the same shard. */
	if (!block)
		shards = num_shards(state->preferred_chain);
	else
		shards = num_shards(block);

	for (i = 0; i < le16_to_cpu(t->num_outputs); i++) {
		if (i == 0)
			the_shard = shard_of(&t->output[i].output_addr, shards);
		else if (shard_of(&t->output[i].output_addr, shards) != the_shard)
			return PROTOCOL_ERROR_TRANS_CROSS_SHARDS;

		if (le32_to_cpu(t->output[i].send_amount) > MAX_SATOSHI)
			return PROTOCOL_ERROR_TOO_LARGE;
	}

	if (!check_trans_sign((const union protocol_transaction *)t,
			      &t->gateway_key, &t->signature))
		return PROTOCOL_ERROR_TRANS_BAD_SIG;
	return PROTOCOL_ERROR_NONE;
}

bool find_output(union protocol_transaction *trans, u16 output_num,
		 struct protocol_address *addr, u32 *amount)
{
	switch (trans->hdr.type) {
	case TRANSACTION_FROM_GATEWAY:
		if (output_num > le16_to_cpu(trans->gateway.num_outputs))
			return false;
		*addr = trans->gateway.output[output_num].output_addr;
		*amount = le32_to_cpu(trans->gateway.output[output_num]
				      .send_amount);
		return true;
	case TRANSACTION_NORMAL:
		if (output_num == 0) {
			/* Spending the send_amount. */
			*addr = trans->normal.output_addr;
			*amount = le32_to_cpu(trans->normal.send_amount);
			return true;
		} else if (output_num == 1) {
			/* Spending the change. */
			pubkey_to_addr(&trans->normal.input_key, addr);
			*amount = le32_to_cpu(trans->normal.change_amount);
			return true;
		}
		return false;
	default:
		abort();
	}
}

#if 0
/* Returns number successfully checked. */
static bool check_chain(struct state *state,
			union protocol_transaction ***trans,
			struct protocol_proof **proof,
			size_t *n,
			bool need_proof)
{
	union protocol_transaction *t;

	if (*n == 0)
		return false;

	t = **trans;
	if (t->hdr.type == TRANSACTION_FROM_GATEWAY) {
		/* Chain ends with a from-gateway transaction. */
		if (check_trans_from_gateway(state, &t->gateway)
		    != PROTOCOL_ERROR_NONE)
			return false;

		if (need_proof) {
			if (!check_merkle(state, t, *proof))
				return false;
			(*proof)++;
		}
		(*trans)++;
		(*n)--;
		return true;
	}
	if (t->hdr.type == TRANSACTION_NORMAL) {
		size_t i;
		u64 total_input = 0;
		struct protocol_address my_addr;

		if (check_trans_normal_basic(state, &t->normal))
			return false;
		if (need_proof) {
			if (!check_merkle(state, t, *proof))
				return false;
			(*proof)++;
		}
		(*trans)++;
		(*n)--;

		/* Get the input address used by this transaction. */
		pubkey_to_addr(&t->normal.input_key, &my_addr);

		/* Consume that many chains. */
		for (i = 0; i < le32_to_cpu(t->normal.num_inputs); i++) {
			u32 amount;
			struct protocol_address addr;
			struct protocol_double_sha sha;

			if (!*n)
				return false;

			/* Make sure transaction is the right one. */
			hash_transaction(**trans, NULL, 0, &sha);
			if (memcmp(&t->normal.input[i].input,
				   &sha, sizeof(sha)) != 0)
				return false;

			if (!find_output(**trans,
					 le16_to_cpu(t->normal.input[i].output),
					 &addr, &amount))
				return false;

			/* Check it was to this address. */
			if (memcmp(&my_addr, &addr, sizeof(addr)) != 0)
				return false;

			total_input += amount;

			/* Check children. */
			if (!check_chain(state, trans, proof, n, true))
				return false;
		}

		/* Numbers must match. */
		if (add_overflows(le32_to_cpu(t->normal.send_amount),
				  le32_to_cpu(t->normal.change_amount)))
			return false;

		if (le32_to_cpu(t->normal.send_amount)
		    + le32_to_cpu(t->normal.change_amount)
		    != total_input)
			return false;

		return true;
	}
	/* Unknown transaction type. */
	return false;
}

/* Transaction consists of a new transaction, followed by a flattened tree
 * of prior transactions. */
bool check_transaction_proof(struct state *state,
			     union protocol_transaction **trans,
			     struct protocol_proof *proof)
{
	size_t n = tal_count(trans);

	assert(n);

	/* You need a proof for every transaction after the first one. */
	if (!proof) {
		if (n != 1)
			return false;
	} else if (tal_count(proof) != n - 1)
		return false;

	if (!check_chain(state, &trans, &proof, &n, false))
		return false;

	/* Must consume all of it. */
	return n == 0;
}
#endif

enum protocol_error check_transaction(struct state *state,
				      const union protocol_transaction *trans,
				      const struct block *block,
				      const struct protocol_input_ref *refs,
				      union protocol_transaction *
				      inputs[TRANSACTION_MAX_INPUTS],
				      unsigned int *bad_input_num)
{
	enum protocol_error e;

	/* If we're in a block, we must have refs. */
	assert(!refs == !block);

	log_debug(state->log, "Checking trans ");
	log_add_struct(state->log, union protocol_transaction, trans);

	switch (trans->hdr.type) {
	case TRANSACTION_FROM_GATEWAY:
		e = check_trans_from_gateway(state, block, &trans->gateway);
		break;
	case TRANSACTION_NORMAL:
		e = check_trans_normal_basic(state, &trans->normal);
		if (!e) {
			unsigned int inputs_known;

			e = check_trans_normal_inputs(state,
						      &trans->normal,
						      block, refs,
						      &inputs_known,
						      inputs,
						      bad_input_num);
			/* FIXME: We currently insist on complete knowledge. */
			if (!e && inputs_known != num_inputs(trans))
				e = PROTOCOL_ERROR_PRIV_TRANS_BAD_INPUT;
		}
		break;
	default:
		e = PROTOCOL_ERROR_TRANS_UNKNOWN;
		break;
	}

	if (e) {
		log_debug(state->log, "It was bad: ");
		log_add_enum(state->log, enum protocol_error, e);
	}
	return e;
}
