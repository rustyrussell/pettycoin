#include "create_transaction.h"
#include "check_transaction.h"
#include "hash_transaction.h"
#include "merkle_transactions.h"
#include "version.h"
#include "talv.h"
#include <ccan/tal/tal.h>
#include <ccan/array_size/array_size.h>
#include <openssl/ecdsa.h>
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

static bool pack_signature(struct protocol_signature *signature,
			   const struct protocol_double_sha *sha,
			   EC_KEY *private_key)
{
	ECDSA_SIG *sig;
	unsigned int len;

	sig = ECDSA_do_sign(sha->sha, SHA256_DIGEST_LENGTH, private_key);
	if (!sig)
		return false;

	/* See https://github.com/sipa/bitcoin/commit/a81cd9680.
	 * There can only be one signature with an even S, so make sure we
	 * get that one. */
	if (BN_is_odd(sig->s)) {
		const EC_GROUP *group;
		BIGNUM order;

		BN_init(&order);
		group = EC_KEY_get0_group(private_key);
		EC_GROUP_get_order(group, &order, NULL);
		BN_sub(sig->s, &order, sig->s);
		BN_free(&order);

		assert(!BN_is_odd(sig->s));
        } 

	/* Pack r and s into signature, 32 bytes each. */
	memset(signature, 0, sizeof(*signature));
	len = BN_num_bytes(sig->r);
	assert(len <= ARRAY_SIZE(signature->r));
	BN_bn2bin(sig->r, signature->r + ARRAY_SIZE(signature->r) - len);
	len = BN_num_bytes(sig->s);
	assert(len <= ARRAY_SIZE(signature->s));
	BN_bn2bin(sig->s, signature->s + ARRAY_SIZE(signature->s) - len);

	ECDSA_SIG_free(sig);
	return true;
}

union protocol_transaction *
create_gateway_transaction(struct state *state,
			   const struct protocol_pubkey *gateway_key,
			   u32 num_payments,
			   struct protocol_gateway_payment *payment,
			   EC_KEY *private_key)
{
	struct protocol_double_sha sha;
	union protocol_transaction *ut;
	struct protocol_transaction_gateway *t;

	ut = alloc_transaction(state, TRANSACTION_FROM_GATEWAY, num_payments);
	t = &ut->gateway;

	t->gateway_key = *gateway_key;
	t->num_outputs = cpu_to_le16(num_payments);
	memcpy(t->output, payment, sizeof(t->output[0]) * num_payments);

	hash_transaction(ut, NULL, 0, &sha);
	if (!pack_signature(&t->signature, &sha, private_key))
		return tal_free(ut);

	return ut;
}

union protocol_transaction *
create_normal_transaction(struct state *state,
			  const struct protocol_address *pay_to,
			  u32 send_amount,
			  u32 change_amount,
			  u16 num_inputs,
			  const struct protocol_input inputs[],
			  EC_KEY *private_key)
{
	union protocol_transaction *ut;
	struct protocol_transaction_normal *t;
	unsigned char *p;
	struct protocol_double_sha sha;

	ut = alloc_transaction(state, TRANSACTION_NORMAL, num_inputs);
	t = &ut->normal;

	/* Create public key ourselves, saves them passing it in. */
	p = t->input_key.key;
	if (i2o_ECPublicKey(private_key, &p) != sizeof(t->input_key))
		return tal_free(ut);

	t->output_addr = *pay_to;
	t->send_amount = cpu_to_le32(send_amount);
	t->change_amount = cpu_to_le32(change_amount);

	t->num_inputs = cpu_to_le16(num_inputs);
	memcpy(t->input, inputs, sizeof(t->input[0]) * num_inputs);

	hash_transaction(ut, NULL, 0, &sha);
	if (!pack_signature(&t->signature, &sha, private_key))
		return tal_free(ut);

	return ut;
}
