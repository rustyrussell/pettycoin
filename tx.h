#ifndef PETTYCOIN_TX_H
#define PETTYCOIN_TX_H
#include "config.h"
#include "protocol.h"
#include <assert.h>
#include <stdbool.h>
#include <stdlib.h>

static inline enum protocol_tx_type tx_type(const union protocol_tx *tx)
{
	return (enum protocol_tx_type)tx->hdr.type;
}

/* Only normal transactions have inputs; 0 for others. */
static inline u32 num_inputs(const union protocol_tx *tx)
{
	switch (tx_type(tx)) {
	case TX_NORMAL:
		return le32_to_cpu(tx->normal.num_inputs);
	case TX_FROM_GATEWAY:
		return 0;
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
		return le16_to_cpu(tx->gateway.num_outputs);
	}
	abort();
}

/* Find the output_num'th output in trans */
bool find_output(const union protocol_tx *trans, u16 output_num,
		 struct protocol_address *addr, u32 *amount);

/* We know tx duplicated inp, but which one? */
u32 find_matching_input(const union protocol_tx *tx,
			const struct protocol_input *inp);

static inline struct protocol_input *
get_normal_inputs(const struct protocol_tx_normal *tx)
{
	/* Inputs follow tx. */
	return (struct protocol_input *)(tx + 1);
}

static inline struct protocol_gateway_payment *
get_gateway_outputs(const struct protocol_tx_gateway *tx)
{
	/* Outputs follow tx. */
	return (struct protocol_gateway_payment *)(tx + 1);
}

static inline const struct protocol_input *
tx_input(const union protocol_tx *tx, unsigned int num)
{
	assert(tx_type(tx) == TX_NORMAL);
	assert(num < num_inputs(tx));
	return &get_normal_inputs(&tx->normal)[num];
}
#endif /* PETTYCOIN_TX_H */
