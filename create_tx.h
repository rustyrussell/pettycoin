#ifndef PETTYCOIN_CREATE_TX_H
#define PETTYCOIN_CREATE_TX_H
#include "config.h"
#include "protocol.h"
#include <ccan/tal/tal.h>
#include <openssl/ec.h>

union protocol_tx *
create_from_gateway_tx(const tal_t *ctx,
		       const struct protocol_pubkey *gateway_key,
		       u16 num_payments,
		       struct protocol_gateway_payment *payment,
		       bool pay_fee,
		       EC_KEY *private_key);

union protocol_tx *
create_normal_tx(const tal_t *ctx,
		 const struct protocol_address *pay_to,
		 u32 send_amount,
		 u32 change_amount,
		 u32 num_inputs,
		 bool pay_fee,
		 const struct protocol_input inputs[],
		 EC_KEY *private_key);

union protocol_tx *
create_to_gateway_tx(const tal_t *ctx,
		     const struct protocol_address *pay_to,
		     u32 send_amount,
		     u32 change_amount,
		     u32 num_inputs,
		     bool pay_fee,
		     const struct protocol_input inputs[],
		     EC_KEY *private_key);
#endif /* PETTYCOIN_CREATE_TX_H */
