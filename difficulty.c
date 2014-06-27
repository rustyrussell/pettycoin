#include <ccan/err/err.h>
#include <openssl/bn.h>
#include <assert.h>
#include "difficulty.h"
#include "sslerrorstring.h"
#include "block.h"
#include "chain.h"
#include "state.h"

/* Based on bitcoin's difficulty calculation, with two differences:
 * 1) We don't have a sign bit in the mantissa.
 * 2) We don't have an out-by-one error in the difficulty timing calculation.
 *
 * The hash must be lower than this value to win.
 */

/*
 * Top 8 bits are exponent, in *bytes* (ie. multiply by 8 to get bits).
 * Botton 24 bits are value.
 */
bool decode_difficulty(u32 difficulty, BIGNUM *n)
{
	BN_init(n);
	if (!BN_set_word(n, difficulty & 0x00FFFFFF)
	    || !BN_lshift(n, n, ((difficulty >> 24) - 3) * 8))
		return false;
	return true;
}

u32 difficulty_one_sixteenth(u32 difficulty)
{
	u32 exp = (difficulty >> 24);
	u32 mantissa = difficulty & 0x00FFFFFF;

	/* Will it overflow? */
	if ((mantissa << 4) & 0xFF000000) {
		if (exp == SHA256_DIGEST_LENGTH - 1)
			mantissa = 0x00FFFFFF;
		else {
			/* Make it 256 times easier. */
			exp++;
			/* Now make it 16 times harder. */
			mantissa >>= 4;
		}
	} else
		mantissa <<= 4;

	return (exp << 24) | mantissa;
}
		
static bool encode_difficulty(u32 *exp, u32 *mantissa, BIGNUM *target)
{
	BIGNUM n;

	/* Get exponent. */
	*exp = BN_num_bytes(target);

	/* Impossibly tiny numbers imply SHA256 has been broken. */
	if (*exp <= 3)
		return false;

	BN_init(&n);
	if (!BN_rshift(&n, target, 8 * (*exp - 3))) {
		BN_free(&n);
		return false;
	}

	*mantissa = BN_get_word(&n);
	assert(*mantissa < 0x00FFFFFF);

	BN_free(&n);
	return true;
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
	BIGNUM target;
	u32 prev_difficulty, exp, base;
	u32 genesis_exp, genesis_base;
	const struct block *genesis = genesis_block(state), *start;

	const u32 interval = PROTOCOL_DIFFICULTY_UPDATE_BLOCKS;
	const u64 ideal_time = PROTOCOL_BLOCK_TARGET_TIME * interval;

	prev_difficulty = le32_to_cpu(prev->tailer->difficulty);

	/* Same as last block? */
	if ((le32_to_cpu(prev->hdr->depth) + 1) % interval)
		return prev_difficulty;

	/* This creates an out-by-one error for genesis period: that's OK */
	if (le32_to_cpu(prev->hdr->depth) == interval - 1)
		start = genesis;
	else
	/* Bitcoin has this out-by-one error, but nice to test against it. */
#ifdef BITCOIN_COMPAT
		start = block_ancestor(prev, interval-1);
#else
		start = block_ancestor(prev, interval);
#endif

	actual_time = (s64)le32_to_cpu(prev->tailer->timestamp)
		- (s64)le32_to_cpu(start->tailer->timestamp);

	/* Don't change by more than a factor of 4. */
	if (actual_time < ideal_time / 4)
		actual_time = ideal_time / 4;
	if (actual_time > ideal_time * 4)
		actual_time = ideal_time * 4;

	/* Expand compact form difficulty number into bignum to work with. */
	BN_init(&target);

	/* Top 8 bits are exponent, in bytes */
	if (!decode_difficulty(prev_difficulty, &target))
		goto fail;

	/* Now scale target by how long it actually took. */
	if (!BN_mul_word(&target, actual_time)
	    || BN_div_word(&target, ideal_time) == (BN_ULONG)-1)
		goto fail;

	if (!encode_difficulty(&exp, &base, &target))
		goto fail;

	BN_free(&target);

	/* Don't go below genesis block difficulty! */
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
