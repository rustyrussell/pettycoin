/*
 # Example 1 (a gateway injection)
 $ bitcoind -testnet getnewaddress
 mwATgTqtQmAP4obu4tvc7i8Z9Q9qNhxqsN
 $ bitcoind -testnet dumpprivkey mwATgTqtQmAP4obu4tvc7i8Z9Q9qNhxqsN
 cTQSBNmMkbCUdFetsnSfzdAiJcdngQsKLyYWVTKgm6fE9GLN74qR
 $ ./inject gateway cTQSBNmMkbCUdFetsnSfzdAiJcdngQsKLyYWVTKgm6fE9GLN74qR localhost 56344 P-mwATgTqtQmAP4obu4tvc7i8Z9Q9qNhxqsN 100
 6ac5ce095cb096d16ab81cf276486615df8714105bc0672639bbc31bfd8071c1

 # Example 2 (using that gateway injection to pay someone else)
 $ bitcoind -testnet getnewaddress
 mv5fpRMAhaPV9LBrAk3MaBH8FG13TpqTxD
 $ bitcoind -testnet dumpprivkey mv5fpRMAhaPV9LBrAk3MaBH8FG13TpqTxD
 cUjJCgPjWAdsJBm85zwCg7ekLYkeeRRoUmkNk3wYydrhbHYKxnwt
 $ ./inject tx cTQSBNmMkbCUdFetsnSfzdAiJcdngQsKLyYWVTKgm6fE9GLN74qR localhost 56344 50 50 6ac5ce095cb096d16ab81cf276486615df8714105bc0672639bbc31bfd8071c1/0
*/
#include <ccan/err/err.h>
#include <ccan/net/net.h>
#include <ccan/read_write_all/read_write_all.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <netdb.h>
#include "base58.h"
#include "create_transaction.h"
#include "protocol_net.h"
#include "marshall.h"
#include "netaddr.h"
#include "addr.h"
#include "hash_transaction.h"
#include "log.h"
#include <string.h>
#include <assert.h>
#include <openssl/obj_mac.h>

#define log_enum_and_exit(message, enumtype, val) \
	log_enum_and_exit_((message), stringify(enumtype), (val))

static void log_enum_and_exit_(const char *message, const char *enumtype,
			       unsigned int val)
{
	log_broken(NULL, "%s", message);
	log_add_enum_(NULL, enumtype, val);
	fprintf(stderr, "\n");
	exit(1);
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

static EC_KEY *get_privkey(const char *arg, struct protocol_pubkey *gkey)
{
	size_t keylen;
	u8 keybuf[1 + 32 + 1 + 4], *pubkey;
	u8 csum[4];
	EC_KEY *priv = EC_KEY_new_by_curve_name(NID_secp256k1);
	BIGNUM bn;

	if (!raw_decode_base58(&bn, arg))
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

static void exchange_welcome(int fd, const struct protocol_net_address *netaddr)
{
	struct protocol_net_hdr hdr;
	struct protocol_req_welcome *w;
	struct protocol_resp_err wresp;

	if (!read_all(fd, &hdr, sizeof(hdr)))
		err(1, "Reading welcome header");

	w = (void *)tal_arr(NULL, char, le32_to_cpu(hdr.len));
	w->len = hdr.len;
	w->type = hdr.type;
	if (!read_all(fd, (char *)w + sizeof(hdr),
		      le32_to_cpu(hdr.len) - sizeof(hdr)))
		err(1, "Reading welcome");

	/* Fix it up, but pretend to be interested in the same. */
	w->random++;
	w->listen_port = 0;
	w->you = *netaddr;

	if (!write_all(fd, w, le32_to_cpu(hdr.len)))
		err(1, "Writing welcome");

	/* Now send response to them. */
	wresp.len = cpu_to_le32(sizeof(wresp));
	wresp.type = cpu_to_le32(PROTOCOL_RESP_ERR);
	wresp.error = cpu_to_le32(PROTOCOL_ERROR_NONE);
	if (!write_all(fd, &wresp, sizeof(wresp)))
		err(1, "Writing welcome response");

	if (!read_all(fd, &wresp, sizeof(wresp)))
		err(1, "Reading welcome response");

	if (wresp.type != cpu_to_le32(PROTOCOL_RESP_ERR))
		log_enum_and_exit("Bad response type ", enum protocol_resp_type,
				  le32_to_cpu(wresp.type));

	if (wresp.error != cpu_to_le32(PROTOCOL_ERROR_NONE))
		log_enum_and_exit("Response error ", enum protocol_error,
				  le32_to_cpu(wresp.error));

	if (wresp.len != cpu_to_le32(sizeof(wresp)))
		errx(1, "Bad welcome response length %u",
		     le32_to_cpu(wresp.len));

}

static void read_response(int fd)
{
	struct protocol_resp_new_transaction resp;

	if (!read_all(fd, &resp, sizeof(resp)))
		err(1, "Reading response");

	if (resp.type != cpu_to_le32(PROTOCOL_RESP_NEW_TRANSACTION))
		log_enum_and_exit("Unexpected response type ",
				  enum protocol_resp_type,
				  le32_to_cpu(resp.type));

	if (resp.error != cpu_to_le32(PROTOCOL_ERROR_NONE))
		log_enum_and_exit("Response gave error ", enum protocol_error,
				  le32_to_cpu(resp.error));

	if (resp.len != cpu_to_le32(sizeof(resp)))
		errx(1, "Unexpected response len %u", le32_to_cpu(resp.len));
}

static void usage(void)
{
	errx(1, "Usage: inject gateway <privkey> <peer> <port> <dstaddr> <satoshi>\n"
		"   inject tx <privkey> <peer> <port> <dstaddr> <satout> <change> <tx>[/<out>]...");
}

static struct protocol_double_sha parse_sha(const char *shastr)
{
	unsigned int i;
	struct protocol_double_sha sha;

	for (i = 0; i < 32; i++) {
		unsigned int v;

		if (sscanf(shastr + i*2, "%02x", &v) != 1)
			errx(1, "Bad sha '%s'", shastr);
		sha.sha[i] = v;
	}
	return sha;
}

/* Simple test code to create a gateway transaction */
int main(int argc, char *argv[])
{
	union protocol_transaction *t;
	struct protocol_gateway_payment payment;
	struct protocol_net_address netaddr;
	bool test_net;
	struct addrinfo *a;
	int fd;
	size_t len;
	struct protocol_net_hdr hdr;
	bool gateway = false;
	bool tx = false;
	struct protocol_double_sha sha;

	if (argv[1] && streq(argv[1], "gateway"))
		gateway = true;
	else if (argv[1] && streq(argv[1], "tx"))
		tx = true;
	else
		usage();

	if (gateway) {
		struct protocol_pubkey gkey;
		EC_KEY *key;

		if (argc != 7)
			usage();
		key = get_privkey(argv[2], &gkey);

		payment.send_amount = cpu_to_le32(atoi(argv[6]));
		if (!pettycoin_from_base58(&test_net, &payment.output_addr,
					   argv[5]))
			errx(1, "Invalid dstaddr");
		if (!test_net)
			errx(1, "dstaddr is not on test net!");

		t = create_gateway_transaction(NULL, &gkey, 1, 0, &payment, key);
	} else if (tx) {
		struct protocol_pubkey destkey;
		EC_KEY *key;
		struct protocol_input input[argc - 8];
		unsigned int i;
		struct protocol_address destaddr;

		if (argc < 9)
			usage();

		key = get_privkey(argv[2], &destkey);
		pubkey_to_addr(&destkey, &destaddr);
		for (i = 0; i < argc - 8; i++) {
			input[i].input = parse_sha(argv[8+i]);
			input[i].output = atoi(argv[8+i] + 64);
		}
		t = create_normal_transaction(NULL, &destaddr, atoi(argv[6]),
					      atoi(argv[7]), argc - 8, input,
					      key);
	}

	len = marshall_transaction_len(t);
	if (!len)
		errx(1, "Marshalling transaction failed");

	a = net_client_lookup(argv[3], argv[4], AF_UNSPEC, SOCK_STREAM);
	if (!a)
		errx(1, "Failed to look up address %s:%s", argv[2], argv[3]);

	if (!addrinfo_to_netaddr(&netaddr, a))
		err(1, "Failed to convert net address");

	fd = net_connect(a);
	if (fd < 0)
		err(1, "Failed to connect to %s:%s", argv[3], argv[4]);
	freeaddrinfo(a);

	exchange_welcome(fd, &netaddr);

	hdr.len = cpu_to_le32(len + sizeof(struct protocol_net_hdr));
	hdr.type = cpu_to_le32(PROTOCOL_REQ_NEW_TRANSACTION);
	if (!write_all(fd, &hdr, sizeof(hdr)))
		err(1, "Failed writing header");
	if (!write_all(fd, t, len))
		err(1, "Failed writing transaction");

	read_response(fd);

	hash_transaction(t, NULL, 0, &sha);
	log_info(NULL, "%s", "");
	log_add_struct(NULL, struct protocol_double_sha, &sha);
	printf("\n");
	return 0;
}
