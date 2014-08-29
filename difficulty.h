#ifndef PETTYCOIN_DIFFICULTY_H
#define PETTYCOIN_DIFFICULTY_H
#include "config.h"
#include "protocol.h"
#include <assert.h>
#include <ccan/short_types/short_types.h>
#include <openssl/bn.h>
#include <stdbool.h>

struct state;
struct block;

u32 get_difficulty(struct state *state, const struct block *prev);

bool decode_difficulty(u32 difficulty, BIGNUM *n);

/* Get 1/16 of difficulty value. */
u32 difficulty_one_sixteenth(u32 difficulty);

void total_work_done(u32 difficulty, const BIGNUM *prev, BIGNUM *work);

/* Note that SHA from openssl is little endian, not bigendian as
 * blockchain.info et al tend to present. */
static inline bool beats_target(const struct protocol_double_sha *sha,
				u32 difficulty)
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

static inline bool valid_difficulty(u32 difficulty)
{
	u32 exp = (difficulty >> 24);
	u32 mantissa = difficulty & 0x00FFFFFF;

	if (exp >= SHA256_DIGEST_LENGTH)
		return false;

	/* We don't handle extreme difficulties: implies SHA was broken */
	if (exp < 3)
		return false;

	/* Must be normalized. */
	if (mantissa < 0x00010000)
		return false;

	return true;
}
#endif /* PETTYCOIN_DIFFICULTY_H */
