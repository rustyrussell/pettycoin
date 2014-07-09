#ifndef PETTYCOIN_TX_H
#define PETTYCOIN_TX_H
#include "config.h"
#include "protocol.h"
#include <assert.h>
#include <stdbool.h>
#include <stdlib.h>

/* Only normal transactions have inputs; 0 for others. */
static inline u32 num_inputs(const union protocol_tx *tx)
{
	switch (tx->hdr.type) {
	case TX_NORMAL:
		return le32_to_cpu(tx->normal.num_inputs);
	case TX_FROM_GATEWAY:
		return 0;
	}
	abort();
}

/* Find the output_num'th output in trans */
bool find_output(const union protocol_tx *trans, u16 output_num,
		 struct protocol_address *addr, u32 *amount);

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
	assert(tx->hdr.type == TX_NORMAL);
	assert(num < num_inputs(tx));
	return &get_normal_inputs(&tx->normal)[num];
}
#endif /* PETTYCOIN_TX_H */
