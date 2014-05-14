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

	/* Connection to the peer. */
	struct io_conn *w, *r;

	/* The error message to send (then close) */
	const void *error_pkt;

	/* Packet we are sending (freed after sending). */
	const void *outgoing;

	/* Pending response to their last request. */
	const void *response;

	/* Packet we have just received. */
	void *incoming;

	/* Outstanding request, if any. */
	enum protocol_req_type curr_in_req, curr_out_req;

	/* The other end's address. */
	struct protocol_net_address you;

	/* For when we sent PROTOCOL_REQ_NEW_TRANS: */
	const struct trans_for_peer *new_trans_pending;

	/* For when we sent PROTOCOL_REQ_BATCH: */
	struct block *batch_requested_block;
	u32 batch_requested_num;

	/* We keep this. */
	struct protocol_req_welcome *welcome;

	/* Last block it knows about. */
	struct block *mutual;

	/* Pending transactions (to send to peer). */
	struct list_head pending;

	/* Complaints about transactions/blocks. */
	struct list_head complaints;

	/* What happened. */
	struct log *log;
};

void new_peer(struct state *state, int fd, const struct protocol_net_address *a);
bool new_peer_by_addr(struct state *state, const char *node, const char *port);

void add_trans_to_peers(struct state *state,
			struct peer *exclude,
			const union protocol_transaction *t);
void remove_trans_from_peers(struct state *state,
			     const union protocol_transaction *t);

void wake_peers(struct state *state);

void complain_to_peers(struct state *state, const struct protocol_net_hdr *pkt);
#endif /* PETTYCOIN_PEER_H */
