/*
 # Example 1 (a gateway injection)
 $ bitcoind -testnet getnewaddress
 mwATgTqtQmAP4obu4tvc7i8Z9Q9qNhxqsN
 $ bitcoind -testnet dumpprivkey mwATgTqtQmAP4obu4tvc7i8Z9Q9qNhxqsN
 cTQSBNmMkbCUdFetsnSfzdAiJcdngQsKLyYWVTKgm6fE9GLN74qR
 $ ./pettycoin-tx gateway cTQSBNmMkbCUdFetsnSfzdAiJcdngQsKLyYWVTKgm6fE9GLN74qR P-mwATgTqtQmAP4obu4tvc7i8Z9Q9qNhxqsN 100
 6ac5ce095cb096d16ab81cf276486615df8714105bc0672639bbc31bfd8071c1

 # Example 2 (using that gateway injection to pay someone else)
 $ bitcoind -testnet getnewaddress
 mv5fpRMAhaPV9LBrAk3MaBH8FG13TpqTxD
 $ bitcoind -testnet dumpprivkey mv5fpRMAhaPV9LBrAk3MaBH8FG13TpqTxD
 cUjJCgPjWAdsJBm85zwCg7ekLYkeeRRoUmkNk3wYydrhbHYKxnwt
 $ ./pettycoin-tx cTQSBNmMkbCUdFetsnSfzdAiJcdngQsKLyYWVTKgm6fE9GLN74qR 50 50 mv5fpRMAhaPV9LBrAk3MaBH8FG13TpqTxD 6ac5ce095cb096d16ab81cf276486615df8714105bc0672639bbc31bfd8071c1/0
*/
#include "addr.h"
#include "base58.h"
#include "create_tx.h"
#include "hash_tx.h"
#include "hex.h"
#include "log.h"
#include "marshal.h"
#include <assert.h>
#include <ccan/err/err.h>
#include <openssl/obj_mac.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

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

static EC_KEY *get_privkey(const char *arg, struct protocol_pubkey *gkey)
{
	size_t keylen;
	u8 keybuf[1 + 32 + 1 + 4], *pubkey;
	u8 csum[4];
	EC_KEY *priv = EC_KEY_new_by_curve_name(NID_secp256k1);
	BIGNUM bn;

	if (!raw_decode_base58(&bn, arg, strlen(arg)))
		errx(1, "Could not decode privkey");

	keylen = BN_num_bytes(&bn);
	/* Pettycoin always uses compressed keys. */
	if (keylen == 1 + 32 + 4)
		errx(1, "Looks like privkey for uncompressed pubkey.");
	if (keylen != 1 + 32 + 1 + 4)
		errx(1, "Privkey length %zu wrong", keylen);
	BN_bn2bin(&bn, keybuf);
	BN_free(&bn);

	base58_get_checksum(csum, keybuf, keylen - sizeof(csum));
	if (memcmp(csum, keybuf + keylen - sizeof(csum), sizeof(csum)) != 0)
		errx(1, "Privkey csum incorrect");

	/* Byte after key should be 1 to represent a compressed key. */
	if (keybuf[1 + 32] != 1)
		errx(1, "Privkey compressed key marker %u incorrect",
		     keybuf[1 + 32]);

	if (keybuf[0] == 128)
		errx(1, "Private key for main network!");
	else if (keybuf[0] != 239)
		errx(1, "Version byte %u not a private key for test network",
			keybuf[0]);

	/* We *always* used compressed form keys. */
	EC_KEY_set_conv_form(priv, POINT_CONVERSION_COMPRESSED);

        BN_init(&bn);
        if (!BN_bin2bn(keybuf + 1, 32, &bn))
		err(1, "Creating bignum from key");
        if (!EC_KEY_regenerate_key(priv, &bn))
		err(1, "Regenerating key");

	/* Save public key */ 
	pubkey = gkey->key;
	keylen = i2o_ECPublicKey(priv, &pubkey);
	assert(keylen == sizeof(gkey->key));

	return priv;
}

static void usage(void)
{
	errx(1, "Usage: pettycoin-tx [--no-fee] from-gateway <privkey> <dstaddr> <satoshi>\n"
		"   pettycoin-tx [--no-fee] tx <privkey> <dstaddr> <satout> <change> <tx>[/<out>]...\n"
		"   pettycoin-tx [--no-fee] to-gateway <privkey> <dstaddr> <satout> <change> <tx>[/<out>]..."
);
}

static struct protocol_double_sha parse_txhash(const char *txraw)
{
	size_t len = strlen(txraw) / 2;
	union protocol_tx *tx = malloc(len);
	struct protocol_double_sha sha;

	if (len < sizeof(struct protocol_tx_hdr))
		errx(1, "Short raw tx '%s'", txraw);

	if (!from_hex(txraw, strlen(txraw), (u8 *)tx, len))
		errx(1, "Bad raw tx '%s'", txraw);

	if (marshal_tx_len(tx) != len)
		errx(1, "Bad length raw tx '%s'", txraw);

	/* You can make this crash, of course */
	hash_tx(tx, &sha);
	return sha;
}

static struct protocol_double_sha parse_tx(const char *txstr)
{
	struct protocol_double_sha sha;

	if (strstarts(txstr, "raw:"))
		return parse_txhash(txstr + 4);

	if (!from_hex(txstr, strlen(txstr), &sha.sha, sizeof(sha.sha)))
		errx(1, "Bad sha '%s'", txstr);

	return sha;
}

/* Simple test code to create a transaction */
int main(int argc, char *argv[])
{
	union protocol_tx *tx;
	struct protocol_gateway_payment payment;
	bool test_net;
	bool from_gateway = false;
	bool normal = false;
	bool to_gateway = false;
	bool pay_fee = true;
	char *txhash;

	if (argc < 3)
		usage();
	if (streq(argv[1], "--no-fee")) {
		pay_fee = false;
		argv++;
		argc--;
	}

	if (streq(argv[1], "from-gateway"))
		from_gateway = true;
	else if (streq(argv[1], "tx"))
		normal = true;
	else if (streq(argv[1], "to-gateway"))
		to_gateway = true;
	else
		usage();

	if (from_gateway) {
		struct protocol_pubkey gkey;
		EC_KEY *key;

		if (argc != 5)
			usage();
		key = get_privkey(argv[2], &gkey);

		payment.send_amount = cpu_to_le32(atoi(argv[4]));
		if (!pettycoin_from_base58(&test_net, &payment.output_addr,
					   argv[3], strlen(argv[3])))
			errx(1, "Invalid dstaddr");
		if (!test_net)
			errx(1, "dstaddr is not on test net!");

		tx = create_from_gateway_tx(NULL, &gkey, 1, &payment, pay_fee,
					    key);
	} else if (normal || to_gateway) {
		struct protocol_pubkey destkey;
		EC_KEY *key;
		struct protocol_input input[argc - 6];
		unsigned int i;
		struct protocol_address destaddr;

		if (argc < 7)
			usage();

		if (!pettycoin_from_base58(&test_net, &destaddr, argv[3], strlen(argv[3])))
			errx(1, "Invalid dstaddr %s", argv[3]);
		if (!test_net)
			errx(1, "dstaddr is not on test net!");

		key = get_privkey(argv[2], &destkey);
		for (i = 0; i < argc - 6; i++) {
			input[i].input = parse_tx(argv[6+i]);
			if (argv[6+i][64] == '/')
				input[i].output = cpu_to_le16(atoi(argv[6+i] + 65));
			else
				input[i].output = cpu_to_le16(0);
			input[i].unused = cpu_to_le16(0);
		}
		if (normal)
			tx = create_normal_tx(NULL, &destaddr,
					      atoi(argv[4]),
					      atoi(argv[5]), argc - 6,
					      pay_fee, input, key);
		else
			tx = create_to_gateway_tx(NULL, &destaddr,
						  atoi(argv[4]),
						  atoi(argv[5]), argc - 6,
						  pay_fee, input, key);
	}

	txhash = to_hex(NULL, tx, marshal_tx_len(tx));
	printf("%s", txhash);
	tal_free(txhash);
	return 0;
}
