#include "marshall.h"
#include "shadouble.h"
#include "signature.h"
#include <ccan/cast/cast.h>
#include <ccan/array_size/array_size.h>
#include <openssl/ecdsa.h>
#include <assert.h>
#include <openssl/bn.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>

static struct protocol_signature *get_signature(const union protocol_tx *tx)
{
	switch (tx->hdr.type) {
	case TX_NORMAL:
		return cast_const(struct protocol_signature *,
				  &tx->normal.signature);
	case TX_FROM_GATEWAY:
		return cast_const(struct protocol_signature *,
				  &tx->gateway.signature);
	default:
		abort();
	}
}	

/* Hash without the signature part (since that's TBA) */
static void sighash_tx(const union protocol_tx *tx,
		       struct protocol_double_sha *sha)
{
	size_t sig_offset, len = marshall_tx_len(tx);
	const char *p;
	SHA256_CTX shactx;

	/* Offset of signature in bytes. */
	sig_offset = (char *)get_signature(tx) - (char *)tx;
	p = (const char *)tx;

	/* Get double sha of transaction. */
	SHA256_Init(&shactx);
	SHA256_Update(&shactx, p, sig_offset);
	p += sig_offset + sizeof(struct protocol_signature);
	len -= sig_offset + sizeof(struct protocol_signature);
	SHA256_Update(&shactx, p, len);
	SHA256_Double_Final(&shactx, sha);
}

bool check_tx_sign(const union protocol_tx *tx,
		   const struct protocol_pubkey *key,
		   const struct protocol_signature *signature)
{
	bool ok = false;	
	BIGNUM r, s;
	ECDSA_SIG sig = { &r, &s };
	EC_KEY *eckey = EC_KEY_new_by_curve_name(NID_secp256k1);
	const unsigned char *k = key->key;
	struct protocol_double_sha sha;

	/* Get hash of transaction without sig */
	sighash_tx(tx, &sha);

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
	switch (ECDSA_do_verify(sha.sha, sizeof(sha.sha), &sig, eckey)) {
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


bool sign_tx(union protocol_tx *tx, EC_KEY *private_key)
{
	struct protocol_double_sha sha;
	ECDSA_SIG *sig;
	unsigned int len;
	struct protocol_signature *signature;

	/* Get hash of transaction without sig */
	sighash_tx(tx, &sha);

	sig = ECDSA_do_sign(sha.sha, SHA256_DIGEST_LENGTH, private_key);
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
	signature = get_signature(tx);
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
