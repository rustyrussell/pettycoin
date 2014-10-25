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

void recv_block_reinject(struct state *state,
			 const tal_t *pkt_ctx,
			 const struct block_info *bi);

/* From generator we get them all together, and importantly, there's
 * no point bothering peers to get information about this block. */
bool recv_block_from_generator(struct state *state, struct log *log,
			       const struct protocol_pkt_block *pkt,
			       struct protocol_pkt_shard **shards);

/* The initial "best" block, contained in the welcome packet. */
enum protocol_ecode recv_welcome_block(struct peer *peer,
				       const tal_t *pkt_ctx,
				       const struct protocol_block_header *hdr,
				       size_t len,
				       struct protocol_block_id *id);

/* We have a txhash, can we figure out the tx? */
bool try_resolve_hash(struct state *state,
		      const struct peer *source,
		      struct block *block, u16 shardnum, u8 txoff);

/* Ask about block contents (on startup and syncing) */
void get_block_contents(struct state *state, const struct block *b);
#endif /* PETTYCOIN_RECV_BLOCK_H */
