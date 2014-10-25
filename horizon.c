#include "block_info.h"
#include "horizon.h"
#include "state.h"
#include "timestamp.h"

/* When do transactions in this block expire? */
u32 block_expiry(struct state *state, const struct block_info *bi)
{
	return block_timestamp(bi)
		+ PROTOCOL_TX_HORIZON_SECS(state->test_net);
}

bool block_expired_by(u32 expires, u32 now)
{
	/* We allow line-balls: ie. if exactly on horizon, it's *not* expired. */
	return expires < now;
}
