#ifndef PETTYCOIN_PEER_H
#define PETTYCOIN_PEER_H
#include "protocol_net.h"
#include <ccan/list/list.h>
#include <stdbool.h>

#define MAX_PEERS 64

struct pending_trans;

struct peer {
	/* state->peers list */
	struct list_node list;

	/* Global state. */
	struct state *state;

	/* Who am I? (Useful for bitmaps of peers) */
	unsigned int peer_num;

	/* Are we still syncing with this peer? */
	bool we_are_syncing;

	/* Should we send them tx's (ie. are *they* finished syncing) */
	bool they_are_syncing;

	/* Connection to the peer. */
	struct io_conn *w, *r;

	/* The error message to send (then close) */
	const struct protocol_pkt_err *error_pkt;

	/* Packet we are sending (freed after sending). */
	const void *outgoing;

	/* Pending response to their last request. */
	const void *response;

	/* Packet we have just received. */
	void *incoming;

#if 0
	/* Outstanding request, if any. */
	enum protocol_req_type curr_in_req, curr_out_req;
#endif

	/* The other end's address. */
	struct protocol_net_address you;

	/* For when we sent PROTOCOL_REQ_NEW_TRANS: */
	const struct trans_for_peer *new_trans_pending;

	/* For when we sent PROTOCOL_REQ_BATCH: */
	struct block *batch_requested_block;
	u32 batch_requested_num;

	/* We keep this. */
	struct protocol_pkt_welcome *welcome;

	/* Last block it knows about. */
	struct block *mutual;

	/* Number of requests we have outstanding (see todo.c) */
	unsigned int requests_outstanding;

	/* Packets queued to send to this peer. */
	struct list_head todo;

	/* What happened. */
	struct log *log;
};

void new_peer(struct state *state, int fd, const struct protocol_net_address *a);
bool new_peer_by_addr(struct state *state, const char *node, const char *port);

void send_trans_to_peers(struct state *state,
			 struct peer *exclude,
			 const union protocol_transaction *t);
void remove_trans_from_peers(struct state *state,
			     const union protocol_transaction *t);

void wake_peers(struct state *state);

void send_block_to_peers(struct state *state,
			 struct peer *exclude,
			 const struct block *block);

void broadcast_to_peers(struct state *state,
			const struct protocol_net_hdr *pkt);
#endif /* PETTYCOIN_PEER_H */
