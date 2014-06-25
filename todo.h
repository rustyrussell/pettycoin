#ifndef PETTYCOIN_TODO_H
#define PETTYCOIN_TODO_H
#include <ccan/list/list.h>
#include <ccan/bitmap/bitmap.h>
#include "peer.h"
#include "protocol_net.h"

/* How many things can we ask each peer at once. */
#define MAX_REQUESTS 4

/* Things we need to find out about from peers. */
struct todo_request {
	/* Linked from state->todo. */
	struct list_node list;

	/* Who have we asked? */
	BITMAP_DECLARE(peers_asked, MAX_PEERS);

	/* Who has failed (subset of above) */
	BITMAP_DECLARE(peers_failed, MAX_PEERS);

	/* FIXME: timeout! */

	union {
		struct protocol_net_hdr hdr;
		struct protocol_pkt_get_block get_block;
		struct protocol_pkt_get_shard get_shard;
		struct protocol_pkt_get_children get_children;
		struct protocol_pkt_get_tx_in_block get_tx_in_block;
	} pkt;
};

/* Something (eg. reply, complaint) queued to send to a particular peer. */
struct todo_pkt {
	/* Linked from peer->todo. */
	struct list_node list;

	void *pkt;
};

void todo_add_get_children(struct state *state,
			   const struct protocol_double_sha *block);
void todo_add_get_block(struct state *state,
			const struct protocol_double_sha *block);
void todo_add_get_shard(struct state *state,
			const struct protocol_double_sha *block,
			u16 shardnum);
void todo_add_get_tx_in_block(struct state *state,
			      const struct protocol_double_sha *block,
			      u16 shardnum, u8 txoff);
void todo_for_peer(struct peer *peer, void *pkt);

/* These decrement peer->requests_outstanding if it was outstanding. */
void todo_done_get_children(struct peer *peer,
			    const struct protocol_double_sha *block,
			    bool success);
void todo_done_get_block(struct peer *peer,
			 const struct protocol_double_sha *block,
			 bool success);
void todo_done_get_shard(struct peer *peer,
			 const struct protocol_double_sha *block,
			 u16 shardnum, bool success);
void todo_done_get_tx_in_block(struct peer *peer,
			       const struct protocol_double_sha *block,
			       u16 shardnum, u8 txoff, bool success);

/* Completely forget about this request (ie. block is invalid) */
void todo_forget_about_shard(struct state *state,
			     const struct protocol_double_sha *block,
			     u16 shardnum);

/* Peer has closed, remove it from todo bitmaps */
void remove_peer_from_todo(struct state *state, struct peer *peer);

/* Increments peer->requests_outstanding if return non-NULL. */
void *get_todo_pkt(struct state *state, struct peer *peer);
#endif /* PETTYCOIN_TODO_H */
