#ifndef PETTYCOIN_CREATE_TRANSACTION_H
#define PETTYCOIN_CREATE_TRANSACTION_H
#include "protocol.h"
#include <openssl/ec.h>

struct state;

union protocol_transaction *
create_gateway_transaction(struct state *state,
			   const struct protocol_pubkey *gateway_key,
			   u32 num_payments,
			   struct protocol_gateway_payment *payment,
			   EC_KEY *private_key);

union protocol_transaction *
create_normal_transaction(struct state *state,
			  const struct protocol_address *pay_to,
			  u32 send_amount,
			  u32 change_amount,
			  u16 num_inputs,
			  const struct protocol_input inputs[],
			  EC_KEY *private_key);
#endif /* PETTYCOIN_CREATE_TRANSACTION_H */
