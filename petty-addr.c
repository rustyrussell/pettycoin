/*
 * Helper to decode and encode addresses.
 */
#include "base58.h"
#include <ccan/err/err.h>

/* Simple test code to create a gateway transaction */
int main(int argc, char *argv[])
{
	char *ret;
	struct protocol_address addr;
	bool testnet;

	err_set_progname(argv[0]);

	if (argc != 2)
		errx(1, "Usage: %s <address>", argv[0]);

	if (!pettycoin_from_base58(&testnet, &addr, argv[1], strlen(argv[1])))
		errx(1, "Address '%s' not valid", argv[1]);

	ret = pettycoin_to_base58(NULL, testnet, &addr,
				  !strstarts(argv[1], "P-"));
	printf("%s\n", ret);
	tal_free(ret);
	return 0;
}
