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

enum input_ecode check_one_input(struct state *state,
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

/* FIXME: Detect double spends! */
enum input_ecode check_tx_inputs(struct state *state,
				 const union protocol_tx *tx,
				 unsigned int *bad_input_num)
{
	unsigned int i, known = 0;
	u64 input_total = 0;
	struct protocol_address my_addr;

	/* FIXME: Use cast here so gcc warns if we add new tx type. */
	switch (tx->hdr.type) {
	case TX_FROM_GATEWAY:
		return ECODE_INPUT_OK;
	case TX_NORMAL:
		break;
	default:
		abort();
	}

	/* Get the input address used by this transaction. */
	pubkey_to_addr(&tx->normal.input_key, &my_addr);

	for (i = 0; i < num_inputs(tx); i++) {
		u32 amount;
		enum input_ecode e;
		const struct protocol_input *inp = tx_input(tx, i);
		union protocol_tx *intx;

		intx = txhash_gettx(&state->txhash, &inp->input);
		if (!intx) {
			/* We keep searching for worse errors. */
			*bad_input_num = i;
			continue;
		}
		known++;

		e = check_one_input(state, inp, intx, &my_addr, &amount);
		if (e != ECODE_INPUT_OK) {
			*bad_input_num = i;
			return ECODE_INPUT_BAD;
		}
		input_total += amount;
	}

	if (known != num_inputs(tx))
		return ECODE_INPUT_UNKNOWN;

	if (input_total != (le32_to_cpu(tx->normal.send_amount)
			    + le32_to_cpu(tx->normal.change_amount))) {
		return ECODE_INPUT_BAD_AMOUNT;
	}
	return ECODE_INPUT_OK;
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
			     const struct block *inside_block)
{
	enum protocol_ecode e;

	log_debug(state->log, "Checking tx ");
	log_add_struct(state->log, union protocol_tx, tx);

	switch (tx->hdr.type) {
	case TX_FROM_GATEWAY:
		e = check_tx_from_gateway(state, inside_block, &tx->gateway);
		break;
	case TX_NORMAL:
		e = check_tx_normal_basic(state, &tx->normal);
		break;
	default:
		e = PROTOCOL_ECODE_TX_TYPE_UNKNOWN;
		break;
	}

	if (e) {
		log_debug(state->log, "It was bad: ");
		log_add_enum(state->log, enum protocol_ecode, e);
	}
	return e;
}
