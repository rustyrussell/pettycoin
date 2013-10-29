#ifndef PETTYCOIN_PEER_H
#define PETTYCOIN_PEER_H
#include "protocol_net.h"
#include <stdbool.h>

struct peer {
	/* Global state. */
	struct state *state;

	/* Connection to the peer. */
	struct io_conn *conn;

	/* Packet to free after sending. */
	void *outgoing;

	/* The other end's address. */
	struct protocol_net_address you;

	/* We keep this. */
	struct protocol_req_welcome *welcome;
};

void init_peer_cache(struct state *state);
void new_peer(struct state *state, int fd, const struct protocol_net_address *a);
bool new_peer_by_addr(struct state *state, const char *node, const char *port);
void fill_peers(struct state *state);
#endif /* PETTYCOIN_PEER_H */
