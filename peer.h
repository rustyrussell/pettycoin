#ifndef PETTYCOIN_PEER_H
#define PETTYCOIN_PEER_H
#include "config.h"
#include "block_info.h"
#include "protocol_net.h"
#include "timeout.h"
#include <ccan/list/list.h>
#include <ccan/time/time.h>
#include <stdbool.h>

#define MAX_PEERS 64

struct block;

/* The unmarshalled block they sent to us in welcome packet. */
struct welcome_block {
	size_t len;
	struct protocol_block_id id;
};

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
	struct io_conn *conn;

	/* The fd itself */
	int fd;

	/* The error message to send (then close) */
	const struct protocol_pkt_err *error_pkt;

	/* Packet we are sending (freed after sending). */
	const void *outgoing;

	/* Packet we have just received. */
	void *incoming;

	/* The other end's address. */
	struct protocol_net_address you;
	/* We keep this. */
	struct protocol_pkt_welcome *welcome;
	struct welcome_block wblock;

	/* Timers for various events. */
	struct timeout input_timeout;
	struct timeout output_timeout;

	/* Debugging */
	struct timeabs last_time_in, last_time_out;
	enum protocol_pkt_type last_type_in, last_type_out;
	size_t last_len_in, last_len_out;
	bool out_pending, in_pending;

	/* Number of requests we have outstanding (see todo.c) */
	unsigned int requests_outstanding;

	/* Packets queued to send to this peer. */
	struct list_head todo;

	/* What happened. */
	struct log *log;
};

void connect_to_peer(struct state *state,
		     int fd, const struct protocol_net_address *a);

struct io_plan *peer_connected(struct io_conn *conn, struct state *state,
			       struct protocol_net_address *addr);

bool new_peer_by_addr(struct state *state, const char *node, const char *port);

void send_tx_in_block_to_peers(struct state *state, const struct peer *exclude,
			       struct block *block, u16 shard, u8 txoff);

void send_tx_to_peers(struct state *state, struct peer *exclude,
		      const union protocol_tx *tx);

void wake_peers(struct state *state);

void send_block_to_peers(struct state *state,
			 struct peer *exclude,
			 const struct block *block);

void broadcast_to_peers(struct state *state, const struct protocol_net_hdr *pkt,
			const struct peer *exclude);

enum protocol_ecode
unmarshal_and_check_tx(struct state *state, const char **p, size_t *len,
		       const union protocol_tx **tx);
#endif /* PETTYCOIN_PEER_H */
