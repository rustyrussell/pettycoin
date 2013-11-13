#ifndef PETTYCOIN_PEER_H
#define PETTYCOIN_PEER_H
#include "protocol_net.h"
#include <ccan/list/list.h>
#include <stdbool.h>

struct peer {
	struct list_node list;

	/* Global state. */
	struct state *state;

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

	/* Are we outputting anything? */
	bool output_idle;
	
	/* The other end's address. */
	struct protocol_net_address you;

	/* We keep this. */
	struct protocol_req_welcome *welcome;

	/* Last block it knows about. */
	struct block *mutual;

	/* What happened. */
	struct log *log;
};

void new_peer(struct state *state, int fd, const struct protocol_net_address *a);
bool new_peer_by_addr(struct state *state, const char *node, const char *port);
#endif /* PETTYCOIN_PEER_H */
