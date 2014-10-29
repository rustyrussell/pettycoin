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

u32 num_inputs(const union protocol_tx *tx);
u32 num_outputs(const union protocol_tx *tx);

/* Get the num'th input. */
struct protocol_input *tx_input(const union protocol_tx *tx, unsigned int num);

/* Only makes sense transactions with inputs */
void get_tx_input_address(const union protocol_tx *tx,
			  struct protocol_address *addr);

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

/* Returns 0 on overflow. */
size_t tx_len(const union protocol_tx *tx);

#endif /* PETTYCOIN_TX_H */
