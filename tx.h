#ifndef PETTYCOIN_TX_H
#define PETTYCOIN_TX_H
#include "config.h"
#include "addr.h"
#include "protocol.h"
#include <assert.h>
#include <stdbool.h>
#include <stdlib.h>

static inline enum protocol_tx_type tx_type(const union protocol_tx *tx)
{
	return (enum protocol_tx_type)(tx->hdr.type & ~PROTOCOL_FEE_TYPE);
}

static inline bool tx_pays_fee(const union protocol_tx *tx)
{
	return tx->hdr.type & PROTOCOL_FEE_TYPE;
}

/* TX_NORMAL and TX_TO_GATEWAY have standard inputs, TX_CLAIM has one
 * but the check that it matches needs to be special. */
static inline u32 num_inputs(const union protocol_tx *tx)
{
	switch (tx_type(tx)) {
	case TX_NORMAL:
		return le32_to_cpu(tx->normal.num_inputs);
	case TX_FROM_GATEWAY:
		return 0;
	case TX_TO_GATEWAY:
		return le32_to_cpu(tx->to_gateway.num_inputs);
	case TX_CLAIM:
		return 1;
	}
	abort();
}

static inline u32 num_outputs(const union protocol_tx *tx)
{
	switch (tx_type(tx)) {
	case TX_NORMAL:
		/* A normal tx has a spend and a change output. */
		return 2;
	case TX_FROM_GATEWAY:
		return le16_to_cpu(tx->from_gateway.num_outputs);
	case TX_TO_GATEWAY:
		/* There's an output, but it's not spendable. */
		return 0;
	case TX_CLAIM:
		return 1;
	}
	abort();
}

/* Only makes sense transactions with inputs */
static inline void get_tx_input_address(const union protocol_tx *tx,
					struct protocol_address *addr)
{
	const struct protocol_pubkey *input_key;

	switch (tx_type(tx)) {
	case TX_NORMAL:
		input_key = &tx->normal.input_key;
		goto input_key;
	case TX_FROM_GATEWAY:
		abort();
	case TX_TO_GATEWAY:
		input_key = &tx->to_gateway.input_key;
		goto input_key;
	case TX_CLAIM:
		input_key = &tx->claim.input_key;
		goto input_key;
	}
	abort();

input_key:
	pubkey_to_addr(input_key, addr);
}

/* Used for fee calculation: amount transferred. */
u32 tx_amount_for_fee(const union protocol_tx *tx);

/* Total of outputs; when combined with fee, should equal total of inputs. */
u32 tx_amount_sent(const union protocol_tx *tx);

/* Find the output_num'th output in trans */
bool find_output(const union protocol_tx *trans, u16 output_num,
		 struct protocol_address *addr, u32 *amount);

/* We know tx duplicated inp, but which one? */
u32 find_matching_input(const union protocol_tx *tx,
			const struct protocol_input *inp);

static inline struct protocol_gateway_payment *
get_from_gateway_outputs(const struct protocol_tx_from_gateway *tx)
{
	/* Outputs follow tx. */
	return (struct protocol_gateway_payment *)(tx + 1);
}

static inline struct protocol_input *
tx_input(const union protocol_tx *tx, unsigned int num)
{
	struct protocol_input *inp = NULL;

	/* Inputs follow tx. */
	switch (tx_type(tx)) {
	case TX_NORMAL:
		inp = (struct protocol_input *)(&tx->normal + 1);
		break;
	case TX_TO_GATEWAY:
		inp = (struct protocol_input *)(&tx->to_gateway + 1);
		break;
	case TX_FROM_GATEWAY:
		return NULL;
	case TX_CLAIM:
		inp = (struct protocol_input *)&tx->claim.input;
	}

	if (num >= num_inputs(tx))
		return NULL;

	return inp + num;
}

/* Returns 0 on overflow. */
size_t tx_len(const union protocol_tx *tx);

#endif /* PETTYCOIN_TX_H */
