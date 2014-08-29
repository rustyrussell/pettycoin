#include "addr.h"
#include "block.h"
#include "chain.h"
#include "check_tx.h"
#include "gateways.h"
#include "hash_tx.h"
#include "overflows.h"
#include "protocol.h"
#include "reward.h"
#include "shadouble.h"
#include "shard.h"
#include "signature.h"
#include "state.h"
#include "tx.h"
#include "tx_in_hashes.h"
#include "version.h"
#include <assert.h>
#include <ccan/endian/endian.h>
#include <ccan/structeq/structeq.h>
#include <ccan/tal/tal.h>

static enum protocol_ecode
check_tx_with_inputs_wellformed(u8 version,
				le32 send_amount,
				le32 change_amount,
				le32 num_inputs,
				const union protocol_tx *tx,
				const struct protocol_pubkey *input_key)
{
	if (!version_ok(version))
		return PROTOCOL_ECODE_TX_HIGH_VERSION;

	if (le32_to_cpu(send_amount) > PROTOCOL_MAX_SATOSHI)
		return PROTOCOL_ECODE_TX_TOO_LARGE;

	if (le32_to_cpu(change_amount) > PROTOCOL_MAX_SATOSHI)
		return PROTOCOL_ECODE_TX_TOO_LARGE;

	if (le32_to_cpu(send_amount) + le32_to_cpu(change_amount) == 0)
		return PROTOCOL_ECODE_TX_TOO_SMALL;

	if (le32_to_cpu(num_inputs) > PROTOCOL_TX_MAX_INPUTS)
		return PROTOCOL_ECODE_TX_TOO_MANY_INPUTS;

	if (le32_to_cpu(num_inputs) == 0)
		return PROTOCOL_ECODE_TX_TOO_MANY_INPUTS;

	if (!check_tx_sign(tx, input_key))
		return PROTOCOL_ECODE_TX_BAD_SIG;

	return PROTOCOL_ECODE_NONE;
}

/* Check signature. */
static enum protocol_ecode
check_tx_normal_basic(struct state *state, const union protocol_tx *ntx)
{
	assert(tx_type(ntx) == TX_NORMAL);
	return check_tx_with_inputs_wellformed(ntx->normal.version,
					       ntx->normal.send_amount,
					       ntx->normal.change_amount,
					       ntx->normal.num_inputs,
					       ntx,
					       &ntx->normal.input_key);
}

static enum protocol_ecode
check_tx_to_gateway_basic(struct state *state, const union protocol_tx *tgtx)
{
	enum protocol_ecode e;
	assert(tx_type(tgtx) == TX_TO_GATEWAY);
	e = check_tx_with_inputs_wellformed(tgtx->to_gateway.version,
					    tgtx->to_gateway.send_amount,
					    tgtx->to_gateway.change_amount,
					    tgtx->to_gateway.num_inputs,
					    tgtx,
					    &tgtx->to_gateway.input_key);

	if (e == PROTOCOL_ECODE_NONE) {
		/* We *could* accept payments to anyone, but let's not. */
		if (!accept_gateway(state, &tgtx->to_gateway.to_gateway_addr))
		    e = PROTOCOL_ECODE_TX_BAD_GATEWAY;
	}
	return e;
}

/* We also need check_one_input(). */
static enum protocol_ecode
check_tx_claim(struct state *state, const union protocol_tx *tx)
{
	if (!version_ok(tx->claim.version))
		return PROTOCOL_ECODE_TX_HIGH_VERSION;

	if (le32_to_cpu(tx->claim.amount) > PROTOCOL_MAX_SATOSHI)
		return PROTOCOL_ECODE_TX_TOO_LARGE;

	if (!check_tx_sign(tx, &tx->claim.input_key))
		return PROTOCOL_ECODE_TX_BAD_SIG;

	return PROTOCOL_ECODE_NONE;
}

/* Searches for a spend of this input <= block */
struct txhash_elem *tx_find_doublespend(struct state *state,
					const struct block *block,
					const struct txhash_elem *me,
					const struct protocol_input *inp)
{
	struct inputhash_elem *ie;
	struct inputhash_iter iter;

	/* Check it wasn't already spent. */
	for (ie = inputhash_firstval(&state->inputhash, &inp->input,
				     le16_to_cpu(inp->output), &iter);
	     ie;
	     ie = inputhash_nextval(&state->inputhash, &inp->input,
				    le16_to_cpu(inp->output), &iter)) {
		/* OK, is transaction which spent it the same chain? */
		struct txhash_iter iter;
		struct txhash_elem *te;
		for (te = txhash_firstval(&state->txhash, &ie->used_by, &iter);
		     te;
		     te = txhash_nextval(&state->txhash, &ie->used_by, &iter)) {
			if (te->status == TX_PENDING)
				continue;

			/* Are we supposed to ignore this? */
			if (me && me->u.block == te->u.block
			    && me->shardnum == te->shardnum
			    && me->txoff == te->txoff)
				continue;

			/* This could happen if we can't get refs for block. */
			if (!shard_is_tx(te->u.block->shard[te->shardnum],
					 te->txoff))
				continue;

			if (block_preceeds(te->u.block, block)
			    || block_preceeds(block, te->u.block))
				return te;
		}
	}
	return NULL;
}

/* Not usable for checking TX_CLAIM inputs!  */
enum input_ecode check_simple_input(struct state *state,
				    const struct protocol_input *inp,
				    const union protocol_tx *intx,
				    const struct protocol_address *my_addr,
				    u32 *amount)
{
	struct protocol_address addr;

	if (!find_output(intx, le16_to_cpu(inp->output), &addr, amount))
		return ECODE_INPUT_BAD;

	/* Check it was to this address. */
	if (!structeq(my_addr, &addr)) {
		log_debug(state->log,
			  "Address mismatch against output %i of ",
			  le16_to_cpu(inp->output));
		log_add_struct(state->log, union protocol_tx, intx);
		return ECODE_INPUT_BAD;
	}

	return ECODE_INPUT_OK;
}

/* block contains a TX_CLAIM against reward_block */
bool check_claim_input(struct state *state,
		       const struct block *claim_block,
		       const struct protocol_input *claim_inp,
		       const struct block *reward_block,
		       u16 reward_shard, u8 reward_txoff,
		       const union protocol_tx *reward_tx,
		       const struct protocol_address *my_addr,
		       u32 *amount)
{
	u16 shardnum;
	u8 txoff;

	/* input must refer to one past end of normal outpus. */
	if (le16_to_cpu(claim_inp->output) != num_outputs(reward_tx) + 1)
		return false;

	/* Too soon to get tx, or block empty? */
	if (!reward_get_tx(state, reward_block, claim_block, &shardnum, &txoff))
		return false;

	/* Is this the right transaction to base reward off? */
	if (reward_shard != shardnum || reward_txoff != txoff)
		return false;

	/* Check it was to this address. */
	if (!structeq(my_addr, &reward_block->hdr->fees_to)) {
		log_debug(state->log, "Claim mismatch against block ");
		log_add_struct(state->log, struct protocol_block_id,
			       &reward_block->sha);
		return false;
	}

	*amount = reward_amount(reward_block, reward_tx);
	return ECODE_INPUT_OK;
}

/* If me is set, ignore that one (ie. we're already in block). */
static enum input_ecode check_one_input(struct state *state,
					const struct block *block,
					const struct txhash_elem *me,
					const struct protocol_input *inp,
					const struct protocol_address *my_addr,
					bool is_claim,
					u32 *amount)
{
	const union protocol_tx *intx;
	struct txhash_elem *te;

	te = txhash_gettx_ancestor(state, &inp->input, block);
	if (!te)
		return ECODE_INPUT_UNKNOWN;

	/* We might know tx hash, but not the tx itself. */
	intx = block_get_tx(te->u.block, te->shardnum, te->txoff);
	if (!intx)
		return ECODE_INPUT_UNKNOWN;

	if (is_claim) {
		assert(te->status == TX_IN_BLOCK);
		if (!check_claim_input(state, block, inp,
				       te->u.block, te->shardnum, te->txoff,
				       intx, my_addr, amount))
			return ECODE_INPUT_CLAIM_BAD;
	} else {
		enum protocol_ecode e;
		e = check_simple_input(state, inp, intx, my_addr, amount);
		if (e != PROTOCOL_ECODE_NONE)
			return e;
	}

	/* Doublespend reports work fine for TX_CLAIM, too. */
	if (tx_find_doublespend(state, block, me, inp))
		return ECODE_INPUT_DOUBLESPEND;

	return ECODE_INPUT_OK;
}

bool correct_amount(struct state *state, const union protocol_tx *tx, u32 total)
{
	u32 fee;

	if (tx_pays_fee(tx))
		fee = PROTOCOL_FEE(tx_amount_sent(tx));
	else
		fee = 0;

	if (total != tx_amount_sent(tx) + fee) {
		log_debug(state->log,
			  "Tx inputs %u, sent %u, fee %u: BAD_AMOUNT for ",
			  total, tx_amount_sent(tx), fee);
		log_add_struct(state->log, union protocol_tx, tx);
		return false;
	}
	return true;
}


enum input_ecode check_tx_inputs(struct state *state,
				 const struct block *block,
				 const struct txhash_elem *me,
				 const union protocol_tx *tx,
				 unsigned int *bad_input_num)
{
	unsigned int i, known = 0;
	u32 input_total = 0;
	struct protocol_address my_addr;
	bool is_claim = false;

	switch (tx_type(tx)) {
	case TX_CLAIM:
		is_claim = true;
		goto check_inputs;
	case TX_FROM_GATEWAY:
		return ECODE_INPUT_OK;
	case TX_NORMAL:
		goto check_inputs;
	case TX_TO_GATEWAY:
		goto check_inputs;
	}
	abort();

check_inputs:
	/* Get the input address used by this transaction. */
	get_tx_input_address(tx, &my_addr);

	for (i = 0; i < num_inputs(tx); i++) {
		u32 amount;
		enum input_ecode e;
		const struct protocol_input *inp = tx_input(tx, i);

		e = check_one_input(state, block, me,
				    inp, &my_addr, is_claim, &amount);
		if (e == ECODE_INPUT_UNKNOWN) {
			/* We keep searching for worse errors. */
			*bad_input_num = i;
			continue;
		}
		if (e != ECODE_INPUT_OK) {
			*bad_input_num = i;
			return ECODE_INPUT_BAD;
		}
		known++;
		input_total += amount;
	}

	if (known != num_inputs(tx))
		return ECODE_INPUT_UNKNOWN;

	if (!correct_amount(state, tx, input_total)) {
		/* We can't use a bad amount complaint for TX_CLAIMs. */
		if (tx_type(tx) == TX_CLAIM)
			return ECODE_INPUT_CLAIM_BAD;
		return ECODE_INPUT_BAD_AMOUNT;
	}

	return ECODE_INPUT_OK;
}

/* block is NULL if we're not in a block (ie. pending tx) */
static enum protocol_ecode
check_tx_from_gateway(struct state *state,
		      const struct block *block,
		      const struct protocol_tx_from_gateway *gtx)
{
	u32 i;
	u32 the_shard;
	u8 shard_ord;
	struct protocol_gateway_payment *out;
	struct protocol_address gwaddr;

	if (!version_ok(gtx->version))
		return PROTOCOL_ECODE_TX_HIGH_VERSION;

	pubkey_to_addr(&gtx->gateway_key, &gwaddr);
	if (!accept_gateway(state, &gwaddr))
		return PROTOCOL_ECODE_TX_BAD_GATEWAY;

	out = get_from_gateway_outputs(gtx);

	/* Each output must be in the same shard. */
	if (!block)
		/* FIXME: This is wrong.  gtx might be old, such as in
		 * recv_tx_bad_input()... */
		shard_ord = next_shard_order(state->longest_knowns[0]);
	else
		shard_ord = block->hdr->shard_order;

	for (i = 0; i < le16_to_cpu(gtx->num_outputs); i++) {
		if (i == 0)
			the_shard = shard_of(&out[i].output_addr, shard_ord);
		else if (shard_of(&out[i].output_addr, shard_ord) != the_shard)
			return PROTOCOL_ECODE_TX_CROSS_SHARDS;

		if (le32_to_cpu(out[i].send_amount) > PROTOCOL_MAX_SATOSHI)
			return PROTOCOL_ECODE_TX_TOO_LARGE;

		if (le32_to_cpu(out[i].send_amount) == 0)
			return PROTOCOL_ECODE_TX_TOO_SMALL;
	}

	if (!check_tx_sign((const union protocol_tx *)gtx, &gtx->gateway_key))
		return PROTOCOL_ECODE_TX_BAD_SIG;
	return PROTOCOL_ECODE_NONE;
}

enum protocol_ecode check_tx(struct state *state,
			     const union protocol_tx *tx,
			     const struct block *inside_block)
{
	enum protocol_ecode e;

	e = PROTOCOL_ECODE_TX_TYPE_UNKNOWN;
	switch (tx_type(tx)) {
	case TX_FROM_GATEWAY:
		e = check_tx_from_gateway(state, inside_block,
					  &tx->from_gateway);
		break;
	case TX_NORMAL:
		e = check_tx_normal_basic(state, tx);
		break;
	case TX_TO_GATEWAY:
		e = check_tx_to_gateway_basic(state, tx);
		break;
	case TX_CLAIM:
		e = check_tx_claim(state, tx);
		break;
	}

	if (e) {
		log_debug(state->log, "It was bad: ");
		log_add_enum(state->log, enum protocol_ecode, e);
	}
	return e;
}
