#include "peer.h"
#include "peer_wants.h"
#include "shard.h"
#include "tx.h"
#include "welcome.h"

static bool peer_wants_shard(const struct peer *peer, u16 shard)
{
	const u8 *interests = peer->welcome->interests;

	return interests[shard/8] & (1 << (shard % 8));
}

/* Is this tx in a shard wanted by this peer? */
bool peer_wants_tx(const struct peer *peer, const union protocol_tx *tx)
{
	return peer_wants_shard(peer, shard_of_tx(tx, 16));
}

/* Is this tx in the (other) shard affected by this tx? */
bool peer_wants_tx_other(const struct peer *peer, const union protocol_tx *tx)
{
	u16 shard;

	switch (tx_type(tx)) {
	case TX_FROM_GATEWAY:
		/* These only affect one shard. */
		return false;
	case TX_NORMAL:
		/* This also affects shard of output address. */
		shard = shard_of(&tx->normal.output_addr, 16);
		return peer_wants_shard(peer, shard);
	case TX_TO_GATEWAY:
	case TX_CLAIM:
		/* These only affect one shard (inputs). */
		return false;
	}
	abort();
}
