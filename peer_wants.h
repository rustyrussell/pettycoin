#ifndef PETTYCOIN_PEER_WANTS_H
#define PETTYCOIN_PEER_WANTS_H
#include "config.h"
#include <stdbool.h>

struct peer;
union protocol_tx;

/* Is peer interested in the shard of this tx? */
bool peer_wants_tx(const struct peer *peer,
			 const union protocol_tx *tx);

/* Is peer interested in the (other) shard affected by this tx? */
bool peer_wants_tx_other(const struct peer *peer,
			 const union protocol_tx *tx);
#endif /* PETTYCOIN_PEER_WANTS_H */
