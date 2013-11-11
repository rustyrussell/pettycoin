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
	struct io_conn *conn;

	/* Packet we are sending (freed after sending). */
	const void *outgoing;

	/* Packet we have received. */
	void *incoming;

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
