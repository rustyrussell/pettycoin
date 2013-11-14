#ifndef PETTYCOIN_DIFFICULTY_H
#define PETTYCOIN_DIFFICULTY_H
#include <stdbool.h>
#include <ccan/short_types/short_types.h>
#include <openssl/bn.h>

struct state;
struct block;
struct protocol_double_sha;

u32 get_difficulty(struct state *state, const struct block *prev);
bool beats_target(const struct protocol_double_sha *sha, u32 difficulty);

void total_work_done(u32 difficulty, const BIGNUM *prev, BIGNUM *work);
#endif /* PETTYCOIN_DIFFICULTY_H */
