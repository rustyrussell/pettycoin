#include "create_tx.h"
#include "hash_tx.h"
#include "merkle_txs.h"
#include "signature.h"
#include "tx.h"
#include "version.h"
#include <assert.h>
#include <ccan/tal/tal.h>

static union protocol_tx *
alloc_tx(const tal_t *ctx, enum protocol_tx_type type, u16 num)
{
	union protocol_tx *tx;
	size_t len = 0;
	const char *label;

	switch (type) {
	case TX_NORMAL:
		label = "struct protocol_tx_normal";
		len = sizeof(struct protocol_tx_normal)
			+ num * sizeof(struct protocol_input);
		goto known;
	case TX_FROM_GATEWAY:
		label = "struct protocol_tx_from_gateway";
		len = sizeof(struct protocol_tx_from_gateway)
			+ num * sizeof(struct protocol_gateway_payment);
		goto known;
	case TX_TO_GATEWAY:
		label = "struct protocol_tx_to_gateway";
		len = sizeof(struct protocol_tx_to_gateway)
			+ num * sizeof(struct protocol_input);
		goto known;
	}
	abort();

known:
	tx = tal_alloc_(ctx, len, false, label);
	tx->hdr.version = current_version();
	tx->hdr.type = type;
	tx->hdr.features = 0;

	return tx;
}

union protocol_tx *
create_from_gateway_tx(const tal_t *ctx,
		       const struct protocol_pubkey *gateway_key,
		       u16 num_payments,
		       struct protocol_gateway_payment *payment,
		       EC_KEY *private_key)
{
	union protocol_tx *tx;
	struct protocol_tx_from_gateway *gtx;

	tx = alloc_tx(ctx, TX_FROM_GATEWAY, num_payments);
	gtx = &tx->from_gateway;

	gtx->gateway_key = *gateway_key;
	gtx->num_outputs = cpu_to_le16(num_payments);
	gtx->unused = 0;
	memcpy(get_from_gateway_outputs(gtx), payment,
	       sizeof(payment[0])*num_payments);

	if (!sign_tx(tx, private_key))
		return tal_free(tx);

	return tx;
}

static union protocol_tx *
finish_tx_with_inputs(union protocol_tx *tx,
		      struct protocol_pubkey *tx_pubkey,
		      struct protocol_address *tx_output_addr,
		      le32 *tx_send_amount,
		      le32 *tx_change_amount,
		      le32 *tx_num_inputs,
		      const struct protocol_address *pay_to,
		      u32 send_amount,
		      u32 change_amount,
		      u32 num_inputs,
		      const struct protocol_input inputs[],
		      EC_KEY *private_key)
{
	unsigned char *p;
	unsigned int i;

	/* Create public key ourselves, saves them passing it in. */
	p = tx_pubkey->key;
	if (i2o_ECPublicKey(private_key, &p) != sizeof(*tx_pubkey))
		return tal_free(tx);

	*tx_output_addr = *pay_to;
	*tx_send_amount = cpu_to_le32(send_amount);
	*tx_change_amount = cpu_to_le32(change_amount);

	*tx_num_inputs = cpu_to_le32(num_inputs);
	for (i = 0; i < num_inputs; i++) {
		/* Make sure they don't leave junk here! */
		assert(inputs[i].unused == 0);
		memcpy(tx_input(tx, i), &inputs[i], sizeof(inputs[i]));
	}

	if (!sign_tx(tx, private_key))
		return tal_free(tx);

	return tx;
}

union protocol_tx *
create_normal_tx(const tal_t *ctx,
		 const struct protocol_address *pay_to,
		 u32 send_amount,
		 u32 change_amount,
		 u32 num_inputs,
		 const struct protocol_input inputs[],
		 EC_KEY *private_key)
{
	union protocol_tx *tx = alloc_tx(ctx, TX_NORMAL, num_inputs);

	return finish_tx_with_inputs(tx,
				     &tx->normal.input_key,
				     &tx->normal.output_addr,
				     &tx->normal.send_amount,
				     &tx->normal.change_amount,
				     &tx->normal.num_inputs,
				     pay_to, send_amount, change_amount,
				     num_inputs, inputs,
				     private_key);
}

union protocol_tx *
create_to_gateway_tx(const tal_t *ctx,
		     const struct protocol_address *gateway_addr,
		     u32 send_amount,
		     u32 change_amount,
		     u32 num_inputs,
		     const struct protocol_input inputs[],
		     EC_KEY *private_key)
{
	union protocol_tx *tx = alloc_tx(ctx, TX_TO_GATEWAY, num_inputs);

	return finish_tx_with_inputs(tx,
				     &tx->to_gateway.input_key,
				     &tx->to_gateway.to_gateway_addr,
				     &tx->to_gateway.send_amount,
				     &tx->to_gateway.change_amount,
				     &tx->to_gateway.num_inputs,
				     gateway_addr, send_amount, change_amount,
				     num_inputs, inputs,
				     private_key);
}
