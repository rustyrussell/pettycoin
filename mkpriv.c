#include "addr.h"
#include "shard.h"
#include <assert.h>
#include <ccan/err/err.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/obj_mac.h>
#include <string.h>
#include <unistd.h>

static void do_error(const char *func)
{
	unsigned long e;

	fprintf(stderr, "Error calling %s:\n", func);

	while ((e = ERR_get_error()) != 0)
		fprintf(stderr, "  %s\n", ERR_error_string(e, NULL));
	exit(1);
}

static u32 shard_of_key(const struct protocol_pubkey *key)
{
	struct protocol_address addr;

	pubkey_to_addr(key, &addr);

	return shard_of(&addr, PROTOCOL_INITIAL_SHARD_ORDER);
}

int main(int argc, char *argv[])
{
	int i, len;
	unsigned char *buf, *p;
	struct protocol_pubkey pub;
	EC_KEY *priv;

	if (argc != 2 && argc != 3)
		errx(1, "Usage: mkpriv <keyname> [shardnum]");

	do {
		priv = EC_KEY_new_by_curve_name(NID_secp256k1);
		if (EC_KEY_generate_key(priv) != 1)
			do_error("EC_KEY_generate_key");

		/* We *always* used compressed form keys. */
		EC_KEY_set_conv_form(priv, POINT_CONVERSION_COMPRESSED);

		p = pub.key;
		len = i2o_ECPublicKey(priv, &p);
		assert(len == sizeof(pub.key));
	} while (argv[2] && shard_of_key(&pub) != atoi(argv[2]));

	len = i2d_ECPrivateKey(priv, NULL);
	p = buf = malloc(len);
	if (i2d_ECPrivateKey(priv, &p) != len)
		do_error("i2d_ECPrivateKey");

	printf("static const unsigned char private_%s[] = {", argv[1]);
	for (i = 0; i < len; i++) {
		if (i % 12 == 0)
			printf("\n\t");
		printf("0x%02x%s", buf[i], i == len - 1 ? "" : ",");
	}
	printf("\n};\n");

	printf("static const struct protocol_pubkey public_%s = {\n"
	       "\t.key = { ", argv[1]);
	for (i = 0; i < sizeof(pub.key); i++) {
		if (i && i % 11 == 0)
			printf("\n\t\t ");
		printf("0x%02x%s", pub.key[i], i == sizeof(pub.key) - 1 ? "" : ",");
	}
	printf(" }\n};\n");

	return 0;
}
