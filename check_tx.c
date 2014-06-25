#include <ccan/structeq/structeq.h>
#include "check_tx.h"
#include "tx.h"
#include "block.h"
#include "chain.h"
#include "gateways.h"
#include "hash_tx.h"
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
enum protocol_ecode
check_tx_normal_basic(struct state *state, const struct protocol_tx_normal *ntx)
{
	if (!version_ok(ntx->version))
		return PROTOCOL_ECODE_TX_HIGH_VERSION;

	if (le32_to_cpu(ntx->send_amount) > MAX_SATOSHI)
		return PROTOCOL_ECODE_TX_TOO_LARGE;

	if (le32_to_cpu(ntx->change_amount) > MAX_SATOSHI)
		return PROTOCOL_ECODE_TX_TOO_LARGE;

	if (le32_to_cpu(ntx->num_inputs) > PROTOCOL_TX_MAX_INPUTS)
		return PROTOCOL_ECODE_TX_TOO_MANY_INPUTS;

	if (le32_to_cpu(ntx->num_inputs) == 0)
		return PROTOCOL_ECODE_TX_TOO_MANY_INPUTS;

	if (!check_tx_sign((const union protocol_tx *)ntx,
			   &ntx->input_key, &ntx->signature))
		return PROTOCOL_ECODE_TX_BAD_SIG;

	return PROTOCOL_ECODE_NONE;
}

/* We failed to find it in hash. */
static enum protocol_ecode
find_tx_for_ref(struct state *state,
		const struct block *block,
		const struct protocol_input_ref *ref,
		union protocol_tx **tx)
{
	u32 bnum;
	const struct block *b;

	*tx = NULL;
	if (le32_to_cpu(ref->blocks_ago) > le32_to_cpu(block->hdr->depth))
		return PROTOCOL_ECODE_PRIV_BLOCK_BAD_INPUT_REF;

	/* FIXME: slow */
	bnum = le32_to_cpu(block->hdr->depth) - le32_to_cpu(ref->blocks_ago);
	for (b = block; le32_to_cpu(b->hdr->depth) != bnum; b = b->prev);

	if (le16_to_cpu(ref->shard) >= num_shards(b->hdr))
		return PROTOCOL_ECODE_PRIV_BLOCK_BAD_INPUT_REF;

	if (ref->txoff >= b->shard_nums[ref->shard])
		return PROTOCOL_ECODE_PRIV_BLOCK_BAD_INPUT_REF;

	if (le32_to_cpu(b->tailer->timestamp) + PROTOCOL_TX_HORIZON_SECS
	    < le32_to_cpu(block->tailer->timestamp))
		return PROTOCOL_ECODE_PRIV_BLOCK_BAD_INPUT_REF;

	*tx = block_get_tx(b, le16_to_cpu(ref->shard), ref->txoff);
	if (!*tx)
		/* We just don't know it.  OK */
		return PROTOCOL_ECODE_NONE;

	/* Transaction is actually not the correct one! */
	return PROTOCOL_ECODE_PRIV_BLOCK_BAD_INPUT_REF_TX;
}	

/*
 * Sets inputs[] if transaction has inputs.
 * Sets bad_input_num if PROTOCOL_ECODE_PRIV_TRANS_BAD_INPUT.
 * If refs is non-NULL, ensures that Nth input tx matches ref[N].
 *
 * Otherwise bad_input_num indicates an unknown input.
 *
 * FIXME: Detect double-spends!
 */
static enum protocol_ecode
check_tx_normal_inputs(struct state *state,
		       const struct protocol_tx_normal *tx,
		       const struct block *block,
		       const struct protocol_input_ref *refs,
		       unsigned int *inputs_known,
		       union protocol_tx *inputs[PROTOCOL_TX_MAX_INPUTS],
		       unsigned int *bad_input_num)
{
	unsigned int i, num;
	u64 input_total = 0;
	struct protocol_address my_addr;
	const struct protocol_input *inp = get_normal_inputs(tx);

	/* Get the input address used by this transaction. */
	pubkey_to_addr(&tx->input_key, &my_addr);

	num = le32_to_cpu(tx->num_inputs);
	*inputs_known = 0;

	for (i = 0; i < num; i++) {
		u32 amount;
		struct protocol_address addr;
		struct txhash_iter it;
		struct txhash_elem *te;

		for (te = txhash_firstval(&state->txhash, &inp[i].input, &it);
		     te;
		     te = txhash_nextval(&state->txhash, &inp[i].input, &it)) {
			u16 shardnum;

			inputs[i] = block_get_tx(te->block,
						 te->shardnum, te->txoff);

			/* Not checking in block?  Any location will do. */
			if (!refs)
				break;

			/* Can't be right if block number wrong. */
			if (le32_to_cpu(te->block->hdr->depth)
			    != le32_to_cpu(block->hdr->depth)
			    - le32_to_cpu(refs[i].blocks_ago))
				continue;

			/* Can't be right if transaction number impossible. */
			shardnum = le32_to_cpu(refs[i].shard);
			if (shardnum >= num_shards(te->block->hdr))
				continue;

			if (le32_to_cpu(refs[i].txoff)
			    >= te->block->shard_nums[shardnum])
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
				enum protocol_ecode err;
				/* Do we know what was input_ref referred to? */
				err = find_tx_for_ref(state, block, &refs[i],
						      &inputs[i]);
				if (err)
					return err;
			}
			/* Partial knowledge... */
			continue;
		}

		(*inputs_known)++;

		if (!find_output(inputs[i], le16_to_cpu(inp[i].output),
				 &addr, &amount)) {
			*bad_input_num = i;
			return PROTOCOL_ECODE_PRIV_TX_BAD_INPUT;
		}

		/* Check it was to this address. */
		if (!structeq(&my_addr, &addr)) {
			*bad_input_num = i;
			log_debug(state->log, "Address mismatch against output %i of ", le16_to_cpu(inp[i].output));
			log_add_struct(state->log, union protocol_tx,
				       inputs[i]);
			return PROTOCOL_ECODE_PRIV_TX_BAD_INPUT;
		}

		input_total += amount;
	}

	if (*inputs_known == num) {
		if (input_total != (le32_to_cpu(tx->send_amount)
				    + le32_to_cpu(tx->change_amount))) {
			return PROTOCOL_ECODE_PRIV_TX_BAD_AMOUNTS;
		}
	}
	return PROTOCOL_ECODE_NONE;
}

/* block is NULL if we're not in a block (ie. pending tx) */
enum protocol_ecode
check_tx_from_gateway(struct state *state,
		      const struct block *block,
		      const struct protocol_tx_gateway *gtx)
{
	u32 i;
	u32 the_shard;
	u8 shard_ord;
	struct protocol_gateway_payment *out;

	if (!version_ok(gtx->version))
		return PROTOCOL_ECODE_TX_HIGH_VERSION;

	if (!accept_gateway(state, &gtx->gateway_key))
		return PROTOCOL_ECODE_TX_BAD_GATEWAY;

	out = get_gateway_outputs(gtx);

	/* Each output must be in the same shard. */
	if (!block)
		shard_ord = next_shard_order(state->longest_knowns[0]);
	else
		shard_ord = block->hdr->shard_order;

	for (i = 0; i < le16_to_cpu(gtx->num_outputs); i++) {
		if (i == 0)
			the_shard = shard_of(&out[i].output_addr, shard_ord);
		else if (shard_of(&out[i].output_addr, shard_ord) != the_shard)
			return PROTOCOL_ECODE_TX_CROSS_SHARDS;

		if (le32_to_cpu(out[i].send_amount) > MAX_SATOSHI)
			return PROTOCOL_ECODE_TX_TOO_LARGE;
	}

	if (!check_tx_sign((const union protocol_tx *)gtx,
			      &gtx->gateway_key, &gtx->signature))
		return PROTOCOL_ECODE_TX_BAD_SIG;
	return PROTOCOL_ECODE_NONE;
}

enum protocol_ecode check_tx(struct state *state,
			     const union protocol_tx *tx,
			     const struct block *block,
			     const struct protocol_input_ref *refs,
			     union protocol_tx *inputs[PROTOCOL_TX_MAX_INPUTS],
			     unsigned int *bad_input_num)
{
	enum protocol_ecode e;

	/* If we're in a block, we must have refs. */
	assert(!refs == !block);

	log_debug(state->log, "Checking tx ");
	log_add_struct(state->log, union protocol_tx, tx);

	switch (tx->hdr.type) {
	case TX_FROM_GATEWAY:
		e = check_tx_from_gateway(state, block, &tx->gateway);
		break;
	case TX_NORMAL:
		e = check_tx_normal_basic(state, &tx->normal);
		if (!e) {
			unsigned int inputs_known;

			e = check_tx_normal_inputs(state,
						   &tx->normal,
						   block, refs,
						   &inputs_known,
						   inputs,
						   bad_input_num);
			/* FIXME: We currently insist on complete knowledge. */
			if (!e && inputs_known != num_inputs(tx))
				e = PROTOCOL_ECODE_PRIV_TX_BAD_INPUT;
		}
		break;
	default:
		e = PROTOCOL_ECODE_TX_UNKNOWN;
		break;
	}

	if (e) {
		log_debug(state->log, "It was bad: ");
		log_add_enum(state->log, enum protocol_ecode, e);
	}
	return e;
}
