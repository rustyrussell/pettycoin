#include "create_transaction.h"
#include "check_transaction.h"
#include "hash_transaction.h"
#include "merkle_transactions.h"
#include "signature.h"
#include "version.h"
#include "talv.h"
#include <ccan/tal/tal.h>
#include <assert.h>

static union protocol_transaction *
alloc_transaction(const tal_t *ctx,
		  enum protocol_transaction_type type,
		  u16 num)
{
	union protocol_transaction *t;

	switch (type) {
	case TRANSACTION_NORMAL:
		t = to_union(union protocol_transaction, normal,
			     talv(ctx, struct protocol_transaction_normal,
				  input[num]));
		break;
	case TRANSACTION_FROM_GATEWAY:
		t = to_union(union protocol_transaction, gateway,
			     talv(ctx, struct protocol_transaction_gateway,
				  output[num]));
		break;
	default:
		abort();
	}

	t->hdr.version = current_version();
	t->hdr.type = type;
	t->hdr.features = 0;

	return t;
}

union protocol_transaction *
create_gateway_transaction(struct state *state,
			   const struct protocol_pubkey *gateway_key,
			   u16 num_payments,
			   u32 reward,
			   struct protocol_gateway_payment *payment,
			   EC_KEY *private_key)
{
	union protocol_transaction *ut;
	struct protocol_transaction_gateway *t;

	ut = alloc_transaction(state, TRANSACTION_FROM_GATEWAY, num_payments);
	t = &ut->gateway;

	t->gateway_key = *gateway_key;
	t->num_outputs = cpu_to_le16(num_payments);
	t->unused = 0;
	t->reward = cpu_to_le32(reward);
	memcpy(t->output, payment, sizeof(t->output[0]) * num_payments);

	if (!sign_transaction(ut, private_key))
		return tal_free(ut);

	return ut;
}

union protocol_transaction *
create_normal_transaction(struct state *state,
			  const struct protocol_address *pay_to,
			  u32 send_amount,
			  u32 change_amount,
			  u32 num_inputs,
			  const struct protocol_input inputs[],
			  EC_KEY *private_key)
{
	union protocol_transaction *ut;
	struct protocol_transaction_normal *t;
	unsigned char *p;

	ut = alloc_transaction(state, TRANSACTION_NORMAL, num_inputs);
	t = &ut->normal;

	/* Create public key ourselves, saves them passing it in. */
	p = t->input_key.key;
	if (i2o_ECPublicKey(private_key, &p) != sizeof(t->input_key))
		return tal_free(ut);

	t->output_addr = *pay_to;
	t->send_amount = cpu_to_le32(send_amount);
	t->change_amount = cpu_to_le32(change_amount);

	t->num_inputs = cpu_to_le32(num_inputs);
	memcpy(t->input, inputs, sizeof(t->input[0]) * num_inputs);

	if (!sign_transaction(ut, private_key))
		return tal_free(ut);

	return ut;
}
