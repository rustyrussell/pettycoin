#include "pseudorand.h"
#include <ccan/err/err.h>
#include <openssl/err.h>
#include <openssl/rand.h>

static struct isaac64_ctx isaac64_initted;
struct isaac64_ctx *isaac64;

void pseudorand_init(void)
{
	unsigned char seedbuf[16];

	/* PRNG */
	if (RAND_bytes(seedbuf, sizeof(seedbuf)) != 1)
		errx(1, "Could not seed PRNG: %s",
		     ERR_error_string(ERR_get_error(), NULL));

	isaac64_init(&isaac64_initted, seedbuf, sizeof(seedbuf));
	/* We use a pointer so we will crash if unused before init */
	isaac64 = &isaac64_initted;
}
