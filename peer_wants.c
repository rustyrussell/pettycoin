#include "peer.h"
#include "peer_wants.h"
#include "shard.h"
#include "tx.h"
#include "welcome.h"

static bool peer_wants_shard(const struct peer *peer, u16 shard)
{
	const u8 *interests = (const u8 *)(peer->welcome + 1);

	return interests[shard/8] & (1 << (shard % 8));
}	

/* Is this tx in the shard of this tx? */
bool peer_wants_tx(const struct peer *peer, const union protocol_tx *tx)
{
	return peer_wants_shard(peer,
				shard_of_tx(tx, peer->welcome->shard_order));
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
		shard = shard_of(&tx->normal.output_addr,
				 peer->welcome->shard_order);
		return peer_wants_shard(peer, shard);
	case TX_TO_GATEWAY:
		/* These only affect one shard (inputs). */
		return false;
	}
	abort();
}
