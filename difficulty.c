#include <ccan/err/err.h>
#include <openssl/bn.h>
#include <assert.h>
#include "difficulty.h"
#include "sslerrorstring.h"
#include "block.h"
#include "state.h"

static const struct block *go_back(const struct block *b, u32 num)
{
	unsigned int i;
	const struct block *start = b;

	for (i = 0; i < num; i++)
		b = b->prev;

	assert(b->blocknum == start->blocknum - num);
	return b;
}

/* Based on bitcoin's difficulty calculation, with two differences:
 * 1) We don't have a sign bit in the mantissa.
 * 2) We don't have an out-by-one error in the difficulty timing calculation.
 *    FIXME: Does this help prevent timejacking?  Think harder!
 *
 * Top 8 bits are exponent, in *bytes* (ie. multiply by 8 to get bits).
 * Botton 24 bits are value.
 *
 * The hash must be lower than this value to win.
 */
u32 get_difficulty(struct state *state, const struct block *prev)
{
	s64 actual_time;
	BIGNUM target_base, target;
	u32 prev_difficulty, exp, base;
	u32 genesis_exp, genesis_base;
	const struct block *genesis;

	/* We update difficulty every 2016 blocks, just like bitcoin. */
	const u32 interval = 2016;
#ifdef BITCOIN_COMPAT
	/* Bitcoin has this out-by-one error, but nice to test against it. */
	const u64 ideal_time = 600 * interval;
#else
	const u64 ideal_time = 600 * (interval - 1);
#endif

	prev_difficulty = le32_to_cpu(prev->tailer->difficulty);

	/* Same as last block? */
	if ((prev->blocknum + 1) % interval)
		return prev_difficulty;

	/* We measure from start of interval, not end of last interval!
	 * This avoids special casing the first interval. */
	actual_time = (s64)le32_to_cpu(prev->tailer->timestamp)
		- (s64)le32_to_cpu(go_back(prev, interval-1)->tailer->timestamp);

	/* Don't change by more than a factor of 4. */
	if (actual_time < ideal_time / 4)
		actual_time = ideal_time / 4;
	if (actual_time > ideal_time * 4)
		actual_time = ideal_time * 4;

	/* Expand compact form difficulty number into bignum to work with. */
	BN_init(&target);
	BN_init(&target_base);

	/* Top 8 bits are exponent, in bytes */
	if (!BN_set_word(&target_base, prev_difficulty & 0x00FFFFFF)
	    || !BN_lshift(&target, &target_base,
			  ((prev_difficulty >> 24) - 3) * 8))
		goto fail;

	/* Now scale target by how long it actually took. */
	if (!BN_mul_word(&target, actual_time)
	    || BN_div_word(&target, ideal_time) == (BN_ULONG)-1)
		goto fail;

	/* Get exponent. */
	exp = BN_num_bytes(&target);

	/* Impossibly tiny numbers imply SHA256 has been broken. */
	assert(exp > 3);
		
	BN_rshift(&target_base, &target, 8 * (exp - 3));
	base = BN_get_word(&target_base);
	assert(base < 0x00FFFFFF);

	BN_free(&target);
	BN_free(&target_base);

	/* Don't go below genesis block difficulty! */
	genesis = genesis_block(state);
	genesis_exp = le32_to_cpu(genesis->tailer->difficulty) >> 24;
	genesis_base = le32_to_cpu(genesis->tailer->difficulty) & 0x00FFFFFF;

	if (exp > genesis_exp || (exp == genesis_exp && base > genesis_base)) {
		exp = genesis_exp;
		base = genesis_base;
	}

	return (exp << 24) | base;

fail:
	errx(1, "SSL error: %s", ssl_error_string());
}

/* Note that SHA from openssl is little endian, not bigendian as
 * blockchain.info et al tend to present. */
bool beats_target(const struct protocol_double_sha *sha, u32 difficulty)
{
	unsigned int i;
	u32 exp = (difficulty >> 24);
	u32 base;

	assert(exp <= SHA256_DIGEST_LENGTH);
	assert(exp >= 3);

	/* You need enough trailing zeroes to even have a chance. */
	for (i = exp; i < SHA256_DIGEST_LENGTH; i++)
		if (sha->sha[i])
			return false;

	base = (((u32)sha->sha[exp-1]) << 16
		| ((u32)sha->sha[exp-2]) << 8
		| sha->sha[exp-3]);

	return base < (difficulty & 0x00FFFFFF);
}

void total_work_done(u32 difficulty, const BIGNUM *prev, BIGNUM *work)
{
	BIGNUM target;
	BN_CTX *c = BN_CTX_new();

	if (!c)
		err(1, "Creating new BN_CTX");

	/* Work = 2^256 / (target + 1). */
	BN_init(&target);
	BN_zero(&target);
	if (!BN_set_word(&target, difficulty & 0x00FFFFFF)
	    || !BN_lshift(&target, &target, ((difficulty >> 24) - 3) * 8)
	    || !BN_add(&target, &target, BN_value_one()))
		errx(1, "Calculating work target failed");

	BN_init(work);
	BN_lshift(work, BN_value_one(), 256);

	if (!BN_div(work, NULL, work, &target, c)
	    || !BN_add(work, work, prev))
		errx(1, "Calculating total work failed");

	BN_free(&target);
	BN_CTX_free(c);
}
