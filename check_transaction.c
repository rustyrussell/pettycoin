#include "check_transaction.h"
#include "block.h"
#include "gateways.h"
#include "hash_transaction.h"
#include "overflows.h"
#include "protocol.h"
#include "addr.h"
#include "shadouble.h"
#include "state.h"
#include "version.h"
#include <assert.h>
#include <ccan/endian/endian.h>
#include <ccan/tal/tal.h>
#include <openssl/bn.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>

/* Check signature. */
static bool check_trans_sign(const struct protocol_double_sha *sha,
			     const struct protocol_pubkey *key,
			     const struct protocol_signature *signature)
{
	bool ok = false;	
	BIGNUM r, s;
	ECDSA_SIG sig = { &r, &s };
	EC_KEY *eckey = EC_KEY_new_by_curve_name(NID_secp256k1);
	const unsigned char *k = key->key;

	/* Unpack public key. */
	if (!o2i_ECPublicKey(&eckey, &k, sizeof(key->key)))
		goto out;

	/* S must be even: https://github.com/sipa/bitcoin/commit/a81cd9680 */
	if (signature->s[31] & 1)
		goto out;

	/* Unpack signature. */
	BN_init(&r);
	BN_init(&s);
	if (!BN_bin2bn(signature->r, sizeof(signature->r), &r)
	    || !BN_bin2bn(signature->s, sizeof(signature->s), &s))
		goto free_bns;


	/* Now verify hash with public key and signature. */
	switch (ECDSA_do_verify(sha->sha, sizeof(sha->sha), &sig, eckey)) {
	case 0:
		/* Invalid signature */
		goto free_bns;
	case -1:
		/* Malformed or other error. */
		goto free_bns;
	}

	ok = true;

free_bns:
	BN_free(&r);
	BN_free(&s);

out:
	EC_KEY_free(eckey);
        return ok;
}

/* What does proof say the merkle should be? */
static void proof_merkles_to(const union protocol_transaction *t,
			     const struct protocol_proof *proof,
			     struct protocol_double_sha *sha)
{
	unsigned int i;

	/* Start with hash of transaction. */
	hash_transaction(t, NULL, 0, sha);

	for (i = 0; i < PETTYCOIN_BATCH_ORDER; i++) {
		SHA256_CTX shactx;

		SHA256_Init(&shactx);
		if (le32_to_cpu(proof->num) & (1 << i)) {
			/* We're on the right. */
			SHA256_Update(&shactx, &proof->merkle[i],
				      sizeof(proof->merkle[i]));
			SHA256_Update(&shactx, sha->sha, sizeof(sha->sha));
		} else {
			/* We're on the left. */
			SHA256_Update(&shactx, sha->sha, sizeof(sha->sha));
			SHA256_Update(&shactx, &proof->merkle[i],
				      sizeof(proof->merkle[i]));
		}
		SHA256_Double_Final(&shactx, sha);
	}
}

/* This only examines the main chain: side chains don't count! */
static bool check_merkle(struct state *state,
			 const union protocol_transaction *t,
			 const struct protocol_proof *proof)
{
	struct block *b;
	struct protocol_double_sha merkle;

	proof_merkles_to(t, proof, &merkle);

	/* We could have multiple candidate blocks. */
	b = list_tail(&state->main_chain, struct block, list);
	for (b = block_find(b, proof->blocksig);
	     b;
	     b = block_find(b->prev, proof->blocksig)) {
		u32 merkle_num;

		/* Can't be the right one if not within num transactions */
		if (le32_to_cpu(proof->num)
		    >= le32_to_cpu(b->hdr->num_transactions))
			continue;

		merkle_num = (le32_to_cpu(proof->num) >> PETTYCOIN_BATCH_ORDER);
		if (memcmp(&b->merkles[merkle_num].sha, merkle.sha,
			   sizeof(merkle.sha)) != 0)
			continue;

		/* OK, you showed that some combination of shas based
		 * on this transaction matches block.  Merkle magic! */
		return true;
	}
	return false;
}

bool check_trans_normal(struct state *state,
			const struct protocol_transaction_normal *t)
{
	struct protocol_double_sha sha;

	if (!version_ok(t->version))
		return false;

	if (le32_to_cpu(t->send_amount) > MAX_SATOSHI)
		return false;

	if (le32_to_cpu(t->change_amount) > MAX_SATOSHI)
		return false;

	hash_transaction((const union protocol_transaction *)t, NULL, 0, &sha);
	return check_trans_sign(&sha, &t->input_key, &t->signature);
}

static u32 shard_of(const struct protocol_address *addr)
{
	be32 shard;

	memcpy(&shard, addr->addr, sizeof(shard));
	return be32_to_cpu(shard) & ((1 << PROTOCOL_SHARD_BITS) - 1);
}

enum protocol_error
check_trans_from_gateway(struct state *state,
			 const struct protocol_transaction_gateway *t)
{
	struct protocol_double_sha sha;
	u32 i;
	u32 the_shard;

	if (!version_ok(t->version))
		return PROTOCOL_ERROR_TRANS_HIGH_VERSION;

	if (!accept_gateway(state, &t->gateway_key))
		return PROTOCOL_ERROR_TRANS_BAD_GATEWAY;

	/* Each output must be in the same shard. */
	for (i = 0; i < le16_to_cpu(t->num_outputs); i++) {
		if (i == 0)
			the_shard = shard_of(&t->output[i].output_addr);
		else if (shard_of(&t->output[i].output_addr) != the_shard)
			return PROTOCOL_ERROR_TRANS_CROSS_SHARDS;

		if (le32_to_cpu(t->output[i].send_amount) > MAX_SATOSHI)
			return PROTOCOL_ERROR_TOO_LARGE;
	}

	hash_transaction((const union protocol_transaction *)t, NULL, 0, &sha);
	if (!check_trans_sign(&sha, &t->gateway_key, &t->signature))
		return PROTOCOL_ERROR_TRANS_BAD_SIG;
	return PROTOCOL_ERROR_NONE;
}

bool find_output(union protocol_transaction *trans, u16 output_num,
		 struct protocol_address *addr, u32 *amount)
{
	switch (trans->hdr.type) {
	case TRANSACTION_FROM_GATEWAY:
		if (output_num > le16_to_cpu(trans->gateway.num_outputs))
			return false;
		*addr = trans->gateway.output[output_num].output_addr;
		*amount = le32_to_cpu(trans->gateway.output[output_num]
				      .send_amount);
		return true;
	case TRANSACTION_NORMAL:
		if (output_num == 0) {
			/* Spending the send_amount. */
			*addr = trans->normal.output_addr;
			*amount = le32_to_cpu(trans->normal.send_amount);
			return true;
		} else if (output_num == 1) {
			/* Spending the change. */
			pubkey_to_addr(&trans->normal.input_key, addr);
			*amount = le32_to_cpu(trans->normal.change_amount);
			return true;
		}
		return false;
	default:
		abort();
	}
}

/* Returns number successfully checked. */
static bool check_chain(struct state *state,
			union protocol_transaction ***trans,
			struct protocol_proof **proof,
			size_t *n,
			bool need_proof)
{
	union protocol_transaction *t;

	if (*n == 0)
		return false;

	t = **trans;
	if (t->hdr.type == TRANSACTION_FROM_GATEWAY) {
		/* Chain ends with a from-gateway transaction. */
		if (check_trans_from_gateway(state, &t->gateway)
		    != PROTOCOL_ERROR_NONE)
			return false;

		if (need_proof) {
			if (!check_merkle(state, t, *proof))
				return false;
			(*proof)++;
		}
		(*trans)++;
		(*n)--;
		return true;
	}
	if (t->hdr.type == TRANSACTION_NORMAL) {
		size_t i;
		u64 total_input = 0;
		struct protocol_address my_addr;

		if (!check_trans_normal(state, &t->normal))
			return false;
		if (need_proof) {
			if (!check_merkle(state, t, *proof))
				return false;
			(*proof)++;
		}
		(*trans)++;
		(*n)--;

		/* Get the input address used by this transaction. */
		pubkey_to_addr(&t->normal.input_key, &my_addr);

		/* Consume that many chains. */
		for (i = 0; i < le32_to_cpu(t->normal.num_inputs); i++) {
			u32 amount;
			struct protocol_address addr;
			struct protocol_double_sha sha;

			if (!*n)
				return false;

			/* Make sure transaction is the right one. */
			hash_transaction(**trans, NULL, 0, &sha);
			if (memcmp(&t->normal.input[i].input,
				   &sha, sizeof(sha)) != 0)
				return false;

			if (!find_output(**trans,
					 le16_to_cpu(t->normal.input[i].output),
					 &addr, &amount))
				return false;

			/* Check it was to this address. */
			if (memcmp(&my_addr, &addr, sizeof(addr)) != 0)
				return false;

			total_input += amount;

			/* Check children. */
			if (!check_chain(state, trans, proof, n, true))
				return false;
		}

		/* Numbers must match. */
		if (add_overflows(le32_to_cpu(t->normal.send_amount),
				  le32_to_cpu(t->normal.change_amount)))
			return false;

		if (le32_to_cpu(t->normal.send_amount)
		    + le32_to_cpu(t->normal.change_amount)
		    != total_input)
			return false;

		return true;
	}
	/* Unknown transaction type. */
	return false;
}

/* Transaction consists of a new transaction, followed by a flattened tree
 * of prior transactions. */
bool check_transaction(struct state *state,
		       union protocol_transaction **trans,
		       struct protocol_proof *proof)
{
	size_t n = tal_count(trans);

	assert(n);

	/* You need a proof for every transaction after the first one. */
	if (!proof) {
		if (n != 1)
			return false;
	} else if (tal_count(proof) != n - 1)
		return false;

	if (!check_chain(state, &trans, &proof, &n, false))
		return false;

	/* Must consume all of it. */
	return n == 0;
}
