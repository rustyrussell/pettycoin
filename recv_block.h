#ifndef PETTYCOIN_RECV_BLOCK_H
#define PETTYCOIN_RECV_BLOCK_H
#include "config.h"
#include <stdbool.h>

struct protocol_pkt_block;
struct protocol_pkt_shard;
struct peer;
struct state;
struct log;

/* From a peer we separate block and shard packets. */
enum protocol_ecode recv_block_from_peer(struct peer *peer,
					 const struct protocol_pkt_block *pkt);

enum protocol_ecode recv_shard_from_peer(struct peer *peer,
					 const struct protocol_pkt_shard *pkt);

/* From generator we get them all together, and importantly, there's
 * no point bothering peers to get information about this block. */
bool recv_block_from_generator(struct state *state, struct log *log,
			       const struct protocol_pkt_block *pkt,
			       struct protocol_pkt_shard **shards);

#endif /* PETTYCOIN_RECV_BLOCK_H */
