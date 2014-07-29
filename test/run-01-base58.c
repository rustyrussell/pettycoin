#include "../base58.c"
#include "../addr.h"
#include "helper_key.h"
#include <ccan/structeq/structeq.h>

int main(void)
{
	void *ctx = tal(NULL, char);
	char *p;
	bool test_net;
	struct protocol_address addr, addr2;
	struct protocol_pubkey pubkey, pubkey2;
	EC_KEY *key;

	memset(&addr, 0xFF, sizeof(addr));
	/* Normal net */
	p = pettycoin_to_base58(ctx, false, &addr, false);
	assert(tal_parent(p) == ctx);
	assert(p[0] == 'P');
	assert(strlen(p) < BASE58_ADDR_MAX_LEN);
	assert(strspn(p, enc) == strlen(p));
	memset(&addr2, 0, sizeof(addr2));
	assert(pettycoin_from_base58(&test_net, &addr2, p, strlen(p)));
	assert(test_net == false);
	assert(structeq(&addr, &addr2));

	/* Test net */
	p = pettycoin_to_base58(ctx, true, &addr, false);
	assert(tal_parent(p) == ctx);
	assert(p[0] == 'q');
	assert(strlen(p) < BASE58_ADDR_MAX_LEN);
	assert(strspn(p, enc) == strlen(p));
	memset(&addr2, 0, sizeof(addr2));
	assert(pettycoin_from_base58(&test_net, &addr2, p, strlen(p)));
	assert(test_net == true);
	assert(structeq(&addr, &addr2));

	/* Bitcoin-style, normal net */
	p = pettycoin_to_base58(ctx, false, &addr, true);
	assert(tal_parent(p) == ctx);
	assert(strstarts(p, "P-1"));
	assert(strlen(p) < BASE58_ADDR_MAX_LEN + 2);
	assert(strspn(p+2, enc) == strlen(p+2));
	memset(&addr2, 0, sizeof(addr2));
	assert(pettycoin_from_base58(&test_net, &addr2, p, strlen(p)));
	assert(test_net == false);
	assert(structeq(&addr, &addr2));

	/* Bitcoin-style, test net */
	p = pettycoin_to_base58(ctx, true, &addr, true);
	assert(tal_parent(p) == ctx);
	assert(strstarts(p, "P-m") || strstarts(p, "P-n"));
	assert(strlen(p) < BASE58_ADDR_MAX_LEN + 2);
	assert(strspn(p+2, enc) == strlen(p+2));
	memset(&addr2, 0, sizeof(addr2));
	assert(pettycoin_from_base58(&test_net, &addr2, p, strlen(p)));
	assert(test_net == true);
	assert(structeq(&addr, &addr2));

	/* From our test gateway key */
	key = key_from_base58("P-cRhETWFwVpi7q8Vjs7KqvYYGZC5htvT3ddnd9hJk5znSohTBHRkT",
			      strlen("P-cRhETWFwVpi7q8Vjs7KqvYYGZC5htvT3ddnd9hJk5znSohTBHRkT"),
			      &test_net, &pubkey);
	assert(key);
	assert(test_net == true);

	/* Check pubkey is correct. */
	pubkey_to_addr(&pubkey, &addr);
	p = pettycoin_to_base58(ctx, true, &addr, true);
	assert(streq(p, "P-muzRJJzenB7uKzokx21W2QGobfDEZfiH1u"));

	/* Check we can return it OK (bitcoin style) */
	p = key_to_base58(ctx, true, key, true);
	assert(streq(p, "P-cRhETWFwVpi7q8Vjs7KqvYYGZC5htvT3ddnd9hJk5znSohTBHRkT"));

	/* Now, turn it into pettcoin-style key. */
	p = key_to_base58(ctx, true, key, false);
	assert(strspn(p, enc) == strlen(p));

	/* Convert back, check it is OK. */
	EC_KEY_free(key);
	key = key_from_base58(p, strlen(p), &test_net, &pubkey2);
	assert(key);
	assert(test_net == true);
	assert(structeq(&pubkey, &pubkey2));

	/* FIXME: Test non-test network keys! */

	tal_free(ctx);
	return 0;
}
