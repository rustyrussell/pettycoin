/* Example:
 $ bitcoind -testnet getnewaddress
 mwATgTqtQmAP4obu4tvc7i8Z9Q9qNhxqsN
 $ bitcoind -testnet dumpprivkey mwATgTqtQmAP4obu4tvc7i8Z9Q9qNhxqsN
 cTQSBNmMkbCUdFetsnSfzdAiJcdngQsKLyYWVTKgm6fE9GLN74qR
 $ ./gateway_inject cTQSBNmMkbCUdFetsnSfzdAiJcdngQsKLyYWVTKgm6fE9GLN74qR localhost 56344 P-mwATgTqtQmAP4obu4tvc7i8Z9Q9qNhxqsN 100
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
#include <string.h>
#include <assert.h>
#include <openssl/obj_mac.h>

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

static EC_KEY *get_gatekey(const char *arg, struct protocol_pubkey *gkey)
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

	if (wresp.len != cpu_to_le32(sizeof(wresp))
	    || wresp.type != cpu_to_le32(PROTOCOL_RESP_ERR)
	    || wresp.error != cpu_to_le32(PROTOCOL_ERROR_NONE))
		errx(1, "Bad welcome response %u/%u/%u",
		     le32_to_cpu(wresp.len),
		     le32_to_cpu(wresp.type),
		     le32_to_cpu(wresp.error));
}

static void read_response(int fd)
{
	struct protocol_resp_new_gateway_transaction resp;

	if (!read_all(fd, &resp, sizeof(resp)))
		err(1, "Reading response");

	if (resp.type != cpu_to_le32(PROTOCOL_RESP_NEW_GATEWAY_TRANSACTION))
		errx(1, "Unexpected response type %u", le32_to_cpu(resp.type));

	if (resp.len != cpu_to_le32(sizeof(resp)))
		errx(1, "Unexpected response len %u", le32_to_cpu(resp.len));

	if (resp.error != cpu_to_le32(PROTOCOL_ERROR_NONE))
		errx(1, "Response gave error %u", le32_to_cpu(resp.error));
}

/* Simple test code to create a gateway transaction */
int main(int argc, char *argv[])
{
	EC_KEY *key;
	struct protocol_pubkey gkey;
	union protocol_transaction *t;
	struct protocol_gateway_payment payment;
	struct protocol_net_address netaddr;
	bool test_net;
	struct addrinfo *a;
	int fd;
	size_t len;
	struct protocol_net_hdr hdr;

	if (argc != 6)
		errx(1, "Usage: gateway_inject <privkey> <peer> <port> <dstaddr> <satoshi>");

	key = get_gatekey(argv[1], &gkey);

	payment.send_amount = cpu_to_le32(atoi(argv[5]));
	if (!pettycoin_from_base58(&test_net, &payment.output_addr, argv[4]))
		errx(1, "Invalid dstaddr");
	if (!test_net)
		errx(1, "dstaddr is not on test net!");

	t = create_gateway_transaction(NULL, &gkey, 1, 0, &payment, key);
	len = marshall_transaction_len(t);
	if (!len)
		errx(1, "Marshalling transaction failed");

	a = net_client_lookup(argv[2], argv[3], AF_UNSPEC, SOCK_STREAM);
	if (!a)
		errx(1, "Failed to look up address %s:%s", argv[2], argv[3]);

	if (!addrinfo_to_netaddr(&netaddr, a))
		err(1, "Failed to convert net address");

	fd = net_connect(a);
	if (fd < 0)
		err(1, "Failed to connect to %s:%s", argv[2], argv[3]);
	freeaddrinfo(a);

	exchange_welcome(fd, &netaddr);

	hdr.len = cpu_to_le32(len + sizeof(struct protocol_net_hdr));
	hdr.type = cpu_to_le32(PROTOCOL_REQ_NEW_GATEWAY_TRANSACTION);
	if (!write_all(fd, &hdr, sizeof(hdr)))
		err(1, "Failed writing header");
	if (!write_all(fd, t, len))
		err(1, "Failed writing transaction");

	read_response(fd);

	printf("Transaction sent!\n");
	return 0;
}
