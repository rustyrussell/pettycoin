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

static void usage(void)
{
	errx(1, "Usage: pettycoin-tx [--no-fee] from-gateway <privkey> <dstaddr> <satoshi>\n"
		"   pettycoin-tx [--no-fee] tx <privkey> <dstaddr> <satout> <change> <tx>[/<out>]...\n"
		"   pettycoin-tx [--no-fee] to-gateway <privkey> <dstaddr> <satout> <change> <tx>[/<out>]..."
);
}

static struct protocol_tx_id parse_txhex(const char *txraw, size_t slen)
{
	size_t len = slen / 2;
	union protocol_tx *tx = malloc(len);
	struct protocol_tx_id sha;

	if (len < sizeof(struct protocol_tx_hdr))
		errx(1, "Short raw tx '%s'", txraw);

	if (!from_hex(txraw, slen, (u8 *)tx, len))
		errx(1, "Bad raw tx '%s'", txraw);

	if (marshal_tx_len(tx) != len)
		errx(1, "Bad length raw tx '%s'", txraw);

	/* You can make this crash, of course */
	hash_tx(tx, &sha);
	return sha;
}

static struct protocol_tx_id parse_tx(const char *txstr, le16 *outnum)
{
	struct protocol_tx_id sha;
	const char *slash;
	size_t slen;

	slash = strchr(txstr, '/');
	if (slash) {
		slen = slash - txstr;
		*outnum = cpu_to_le16(atoi(slash + 1));
	} else {
		slen = strlen(txstr);
		*outnum = cpu_to_le16(0);
	}

	if (strstarts(txstr, "raw:"))
		return parse_txhex(txstr + 4, slen - 4);

	if (!from_hex(txstr, slen, &sha.sha, sizeof(sha.sha)))
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

		key = key_from_base58(argv[2], strlen(argv[2]),
				      &test_net, &gkey);
		if (!key)
			errx(1, "Invalid key %s", argv[2]);

		if (!test_net)
			errx(1, "Key is not for test net");

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

		key = key_from_base58(argv[2], strlen(argv[2]),
				      &test_net, &destkey);
		if (!test_net)
			errx(1, "Key is not for test net");

		for (i = 0; i < argc - 6; i++) {
			input[i].input = parse_tx(argv[6+i], &input[i].output);
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
