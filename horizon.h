#ifndef PETTYCOIN_HORIZON_H
#define PETTYCOIN_HORIZON_H
#include "config.h"
#include <ccan/short_types/short_types.h>
#include <stdbool.h>

struct state;
struct block_info;

/* When do transactions in this block expire? */
u32 block_expiry(struct state *state, const struct block_info *bi);

/* Has this expiry time mean it's expired? */
bool block_expired_by(u32 expires, u32 now);

#endif /* PETTYCOIN_HORIZON_H */
