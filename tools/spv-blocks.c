/* Print how many blocks we'd have to keep with an spv skipchain */
#include <stdio.h>
#include <stdlib.h>
#include <ccan/isaac/isaac.h>
#include <ccan/isaac/isaac.c>
#include <ccan/ilog/ilog.h>
#include <ccan/ilog/ilog.c>
#include <err.h>

#define MAX_SKIPBITS 32

/*
 * With 10 second block times, we'll make 8640 blocks a day.
 * => 3153600 blocks a year.
 *
 * This is an overestimate (each year will overlap), but:
 *	for seed in `seq 1000`; do ./spv-blocks 3153600 $seed; done | stats
 *	=> 2777-410045(283135+/-7.5e+04) (max skipped = 2^15-28(18.724+/-1.7))
 *
 * Assuming we merge mine, we need to keep our header (minimum 2 SHA)
 * with back pointer (1 SHA) and proof (5 SHAs) plus proof it's in
 * coinbase (log2(numtxs) SHAs) + coinbase tx (~200 bytes) + bitcoin
 * header (~104 bytes).  Assuming 8000 txs, that's (2 + 1 + 5 + 13) * 32 + 300
 * or say 1Kb.
 *
 * => Average of 280MB of data per year.
 *
 * If we make MAX_SKIPBITS 16, that increases to:
 *    288021-412252(350772+/-2.1e+04) (max skipped = 2^15-16(15.998+/-0.045))
 *
 * Or 350MB per year.
 */
int main(int argc, char *argv[])
{
	struct isaac_ctx isaac;
	unsigned long long i, skip, end, n, max = 0;

	if (argc < 2)
		errx(1, "Usage: spv-blocks <number> [<seed>]");

	isaac_init(&isaac, (void *)argv[2], argv[2] ? strlen(argv[2]) : 0);

	end = atoll(argv[1]);
	for (i = 0, n = 0; i < end; i += (1 << skip), n++) {
		skip = 32 - ilog32(isaac_next_uint32(&isaac));
		if (skip > MAX_SKIPBITS)
			skip = MAX_SKIPBITS;
		if (skip > max)
			max = skip;
	}
	printf("%llu (max skipped = 2^%llu)\n", n, max);
	return 0;
}
