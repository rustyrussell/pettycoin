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
		label = "struct protocol_tx_gateway";
		len = sizeof(struct protocol_tx_gateway)
			+ num * sizeof(struct protocol_gateway_payment);
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
create_gateway_tx(const tal_t *ctx,
		  const struct protocol_pubkey *gateway_key,
		  u16 num_payments,
		  struct protocol_gateway_payment *payment,
		  EC_KEY *private_key)
{
	union protocol_tx *tx;
	struct protocol_tx_gateway *gtx;

	tx = alloc_tx(ctx, TX_FROM_GATEWAY, num_payments);
	gtx = &tx->gateway;

	gtx->gateway_key = *gateway_key;
	gtx->num_outputs = cpu_to_le16(num_payments);
	gtx->unused = 0;
	memcpy(get_gateway_outputs(gtx), payment,
	       sizeof(payment[0])*num_payments);

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
	union protocol_tx *tx;
	struct protocol_tx_normal *ntx;
	unsigned char *p;
	unsigned int i;

	tx = alloc_tx(ctx, TX_NORMAL, num_inputs);
	ntx = &tx->normal;

	/* Create public key ourselves, saves them passing it in. */
	p = ntx->input_key.key;
	if (i2o_ECPublicKey(private_key, &p) != sizeof(ntx->input_key))
		return tal_free(tx);

	ntx->output_addr = *pay_to;
	ntx->send_amount = cpu_to_le32(send_amount);
	ntx->change_amount = cpu_to_le32(change_amount);

	ntx->num_inputs = cpu_to_le32(num_inputs);
	/* Make sure they don't leave junk here! */
	for (i = 0; i < num_inputs; i++)
		assert(inputs[i].unused == 0);
	memcpy(get_normal_inputs(ntx), inputs, sizeof(inputs[0]) * num_inputs);

	if (!sign_tx(tx, private_key))
		return tal_free(tx);

	return tx;
}
