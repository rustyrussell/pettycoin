/* Converted to C by Rusty Russell, based on bitcoin source: */
// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#include "base58.h"
#include "state.h"
#include <assert.h>
#include <ccan/build_assert/build_assert.h>
#include <ccan/tal/str/str.h>
#include <openssl/obj_mac.h>
#include <openssl/sha.h>
#include <string.h>

static const char enc[] =
	"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

static char encode_char(unsigned long val)
{
	assert(val < strlen(enc));
	return enc[val];
}

static int decode_char(char c)
{
	const char *pos = strchr(enc, c);
	if (!pos)
		return -1;
	return pos - enc;
}

/*
 * Encode a byte sequence as a base58-encoded string.  This is a bit
 * weird: returns pointer into buf (or NULL if wouldn't fit).
 */
static char *encode_base58(char *buf, size_t buflen,
			   const u8 *data, size_t data_len)
{
	char *p;
	BIGNUM bn;

	/* Convert to a bignum. */
	BN_init(&bn);
	BN_bin2bn(data, data_len, &bn);

	/* Add NUL terminator */
	if (!buflen) {
		p = NULL;
		goto out;
	}
	p = buf + buflen;
	*(--p) = '\0';

	/* Fill from the back, using a series of divides. */
	while (!BN_is_zero(&bn)) {
		int rem = BN_div_word(&bn, 58);
		if (--p < buf) {
			p = NULL;
			goto out;
		}
		*p = encode_char(rem);
	}

	/* Now, this is really weird.  We pad with zeroes, but not at
	 * base 58, but in terms of zero bytes.  This means that some
	 * encodings are shorter than others! */
	while (data_len && *data == '\0') {
		if (--p < buf) {
			p = NULL;
			goto out;
		}
		*p = encode_char(0);
		data_len--;
		data++;
	}

out:
	BN_free(&bn);
	return p;
}

/*
 * Decode a base58-encoded string into a byte sequence.
 */
bool raw_decode_base58(BIGNUM *bn, const char *src, size_t len)
{
	BN_init(bn);
	BN_zero(bn);

	while (len) {
		int val = decode_char(*src);
		if (val < 0) {
			BN_free(bn);
			return false;
		}
		BN_mul_word(bn, 58);
		BN_add_word(bn, val);
		src++;
		len--;
	}

	return true;
}

void base58_get_checksum(u8 csum[4], const u8 buf[], size_t buflen)
{
	SHA256_CTX sha256;
	u8 sha_result[SHA256_DIGEST_LENGTH];

	/* Form checksum, using double SHA2 (as per bitcoin standard) */
	SHA256_Init(&sha256);
	SHA256_Update(&sha256, buf, buflen);
	SHA256_Final(sha_result, &sha256);
	SHA256_Init(&sha256);
	SHA256_Update(&sha256, sha_result, sizeof(sha_result));
	SHA256_Final(sha_result, &sha256);

	/* Use first four bytes of that as the checksum. */
	memcpy(csum, sha_result, 4);
}

char *pettycoin_to_base58(const tal_t *ctx, bool test_net,
			  const struct protocol_address *addr,
			  bool bitcoin_style)
{
	u8 buf[1 + RIPEMD160_DIGEST_LENGTH + 4];
	char out[BASE58_ADDR_MAX_LEN + 2], *p;

	if (bitcoin_style)
		buf[0] = test_net ? 111 : 0;
	else
		buf[0] = test_net ? PETTY_PREFIX_TESTNET : PETTY_PREFIX;

	BUILD_ASSERT(sizeof(*addr) == RIPEMD160_DIGEST_LENGTH);
	memcpy(buf+1, addr, RIPEMD160_DIGEST_LENGTH);

	/* Append checksum */
	base58_get_checksum(buf + 1 + RIPEMD160_DIGEST_LENGTH,
			    buf, 1 + RIPEMD160_DIGEST_LENGTH);

	p = encode_base58(out, BASE58_ADDR_MAX_LEN, buf, sizeof(buf));

	if (bitcoin_style)
		return tal_fmt(ctx, "P-%s", p);
	else
		return tal_strdup(ctx, p);
}

bool pettycoin_from_base58(bool *test_net,
			   struct protocol_address *addr,
			   const char *base58, size_t base58_len)
{
	u8 buf[1 + RIPEMD160_DIGEST_LENGTH + 4];
	BIGNUM bn;
	size_t len;
	u8 csum[4];
	bool is_bitcoin = false;

	if (base58_len > 2 && strstarts(base58, "P-")) {
		/* pettycoin-ized bitcoin address. */
		is_bitcoin = true;
		base58 += 2;
		base58_len -= 2;
	}

	if (!raw_decode_base58(&bn, base58, base58_len))
		return false;

	len = BN_num_bytes(&bn);
	if (len > sizeof(buf))
		return false;

	memset(buf, 0, sizeof(buf));
	BN_bn2bin(&bn, buf + sizeof(buf) - len);
	BN_free(&bn);

	if (is_bitcoin) {
		if (buf[0] == 111)
			*test_net = true;
		else if (buf[0] == 0)
			*test_net = false;
		else
			return false;
	} else {
		if (buf[0] == PETTY_PREFIX_TESTNET)
			*test_net = true;
		else if (buf[0] == PETTY_PREFIX)
			*test_net = false;
		else
			return false;
	}

	base58_get_checksum(csum, buf, 1 + RIPEMD160_DIGEST_LENGTH);
	if (memcmp(csum, buf + 1 + RIPEMD160_DIGEST_LENGTH, sizeof(csum)) != 0)
		return false;

	BUILD_ASSERT(sizeof(*addr) == RIPEMD160_DIGEST_LENGTH);
	memcpy(addr, buf+1, sizeof(*addr));
	return true;
}

/* buf already contains version and ripemd160.  Append checksum and encode */
char *base58_with_check(char dest[BASE58_ADDR_MAX_LEN],
			u8 buf[1 + RIPEMD160_DIGEST_LENGTH + 4])
{
	/* Append checksum */
	base58_get_checksum(buf + 1 + RIPEMD160_DIGEST_LENGTH,
			    buf, 1 + RIPEMD160_DIGEST_LENGTH);

	/* Now encode. */
	return encode_base58(dest, BASE58_ADDR_MAX_LEN, buf,
			     1 + RIPEMD160_DIGEST_LENGTH + 4);
}

bool ripemd_from_base58(u8 *version, u8 ripemd160[RIPEMD160_DIGEST_LENGTH],
			const char *base58)
{
	u8 buf[1 + RIPEMD160_DIGEST_LENGTH + 4];
	u8 csum[4];
	BIGNUM bn;
	size_t len;

	/* Too long?  Check here before doing arithmetic. */
	if (strlen(base58) > BASE58_ADDR_MAX_LEN - 1)
		return false;

	/* Fails if it contains invalid characters. */
	if (!raw_decode_base58(&bn, base58, strlen(base58)))
		return false;

	/* Too big? */
	len = BN_num_bytes(&bn);
	if (len > sizeof(buf)) {
		BN_free(&bn);
		return false;
	}

	/* Fill start with zeroes. */
	memset(buf, 0, sizeof(buf) - len);
	BN_bn2bin(&bn, buf + sizeof(buf) - len);
	BN_free(&bn);

	/* Check checksum is correct. */
	base58_get_checksum(csum, buf, sizeof(buf));
	if (memcmp(csum, buf + 1 + RIPEMD160_DIGEST_LENGTH, 4) != 0)
		return false;

	*version = buf[0];
	memcpy(ripemd160, buf + 1, RIPEMD160_DIGEST_LENGTH);
	return true;
}

char *key_to_base58(const tal_t *ctx, bool test_net, EC_KEY *key,
		    bool bitcoin_style)
{
	u8 buf[1 + 32 + 1 + 4];
	char out[BASE58_KEY_MAX_LEN + 2], *p;
        const BIGNUM *bn = EC_KEY_get0_private_key(key);
	int len;

	buf[0] = test_net ? 239 : 128;
	/* This is the difference between bitcoin and pettycoin! */
	if (!bitcoin_style)
		buf[0] += 'P' - 'B';

	/* Make sure any zeroes are at the front of number (MSB) */
	len = BN_num_bytes(bn);
	assert(len <= 32);
	memset(buf + 1, 0, 32 - len);
	BN_bn2bin(bn, buf + 1 + 32 - len);

	/* Mark this as a compressed key. */
	buf[1 + 32] = 1;

	/* Append checksum */
	base58_get_checksum(buf + 1 + 32 + 1, buf, 1 + 32 + 1);

	p = encode_base58(out, BASE58_KEY_MAX_LEN, buf, sizeof(buf));

	if (bitcoin_style)
		return tal_fmt(ctx, "P-%s", p);
	else
		return tal_strdup(ctx, p);
}

// Thus function based on bitcoin's key.cpp:
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
static bool EC_KEY_regenerate_key(EC_KEY *eckey, BIGNUM *priv_key)
{
	BN_CTX *ctx = NULL;
	EC_POINT *pub_key = NULL;
	const EC_GROUP *group = EC_KEY_get0_group(eckey);

	if ((ctx = BN_CTX_new()) == NULL)
		return false;

	pub_key = EC_POINT_new(group);
	if (pub_key == NULL)
		return false;

	if (!EC_POINT_mul(group, pub_key, priv_key, NULL, NULL, ctx))
		return false;

	EC_KEY_set_private_key(eckey, priv_key);
	EC_KEY_set_public_key(eckey, pub_key);

	BN_CTX_free(ctx);
	EC_POINT_free(pub_key);
	return true;
}

EC_KEY *key_from_base58(const char *base58, size_t base58_len,
			bool *test_net, struct protocol_pubkey *key)
{
	size_t keylen;
	u8 keybuf[1 + 32 + 1 + 4], *pubkey;
	u8 csum[4];
	EC_KEY *priv;
	BIGNUM bn;
	bool is_bitcoin;

	if (base58_len > 2 && strstarts(base58, "P-")) {
		/* pettycoin-ized bitcoin address. */
		is_bitcoin = true;
		base58 += 2;
		base58_len -= 2;
	} else
		is_bitcoin = false;

	if (!raw_decode_base58(&bn, base58, base58_len))
		return NULL;

	keylen = BN_num_bytes(&bn);
	/* Pettycoin always uses compressed keys. */
	if (keylen == 1 + 32 + 4)
		goto fail_free_bn;
	if (keylen != 1 + 32 + 1 + 4)
		goto fail_free_bn;
	BN_bn2bin(&bn, keybuf);

	base58_get_checksum(csum, keybuf, keylen - sizeof(csum));
	if (memcmp(csum, keybuf + keylen - sizeof(csum), sizeof(csum)) != 0)
		goto fail_free_bn;

	/* Byte after key should be 1 to represent a compressed key. */
	if (keybuf[1 + 32] != 1)
		goto fail_free_bn;

	if (is_bitcoin) {
		if (keybuf[0] == 128)
			*test_net = false;
		else if (keybuf[0] == 239)
			*test_net = true;
		else
			goto fail_free_bn;
	} else {
		if (keybuf[0] == 128 + 'P' - 'B')
			*test_net = false;
		else if (keybuf[0] == 239 + 'P' - 'B')
			*test_net = true;
		else
			goto fail_free_bn;
	}

	priv = EC_KEY_new_by_curve_name(NID_secp256k1);
	/* We *always* used compressed form keys. */
	EC_KEY_set_conv_form(priv, POINT_CONVERSION_COMPRESSED);

	BN_free(&bn);
        BN_init(&bn);
        if (!BN_bin2bn(keybuf + 1, 32, &bn))
		goto fail_free_priv;
        if (!EC_KEY_regenerate_key(priv, &bn))
		goto fail_free_priv;

	/* Save public key */ 
	pubkey = key->key;
	keylen = i2o_ECPublicKey(priv, &pubkey);
	assert(keylen == sizeof(key->key));

	BN_free(&bn);
	return priv;

fail_free_priv:
	EC_KEY_free(priv);
fail_free_bn:
	BN_free(&bn);
	return NULL;
}
