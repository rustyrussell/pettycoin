#ifndef PETTYCOIN_TRANSACTION_H
#define PETTYCOIN_TRANSACTION_H
#include "protocol.h"
#include <stdlib.h>
#include <stdbool.h>

/* Only normal transactions have inputs; 0 for others. */
static inline u32 num_inputs(const union protocol_transaction *t)
{
	switch (t->hdr.type) {
	case TRANSACTION_NORMAL:
		return le32_to_cpu(t->normal.num_inputs);
	case TRANSACTION_FROM_GATEWAY:
		return 0;
	}
	abort();
}

/* Find the output_num'th output in trans */
bool find_output(union protocol_transaction *trans, u16 output_num,
		 struct protocol_address *addr, u32 *amount);

static inline struct protocol_input *
get_normal_inputs(const struct protocol_transaction_normal *tx)
{
	/* Inputs follow transaction. */
	return (struct protocol_input *)(tx + 1);
}

static inline struct protocol_gateway_payment *
get_gateway_outputs(const struct protocol_transaction_gateway *tx)
{
	/* Outputs follow transaction. */
	return (struct protocol_gateway_payment *)(tx + 1);
}
#endif /* PETTYCOIN_TRANSACTION_H */
