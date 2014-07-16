#ifndef PETTYCOIN_PEER_CACHE_H
#define PETTYCOIN_PEER_CACHE_H
#include "config.h"
#include <ccan/short_types/short_types.h>
#include <stdbool.h>

struct state;
struct protocol_net_address;

/* After three hours we consider a peer to have never connected. */
#define PEER_CACHE_MAXSECS	(3 * 60 * 60)

/* +30 minutes for data from other peers (vs. our own direct experience) */
#define PEER_CACHE_PEER_EXTRA	(30 * 60)

void fill_peers(struct state *state);
void init_peer_cache(struct state *state);

void peer_cache_add(struct state *state, 
		    const struct protocol_net_address *addr);
void peer_cache_refresh(struct state *state, 
			const struct protocol_net_address *addr);
struct protocol_net_address *read_peer_cache(struct state *state);
void peer_cache_del(struct state *state,
		    const struct protocol_net_address *addr,
		    bool del_on_disk);
#endif /* PETTYCOIN_PEER_CACHE_H */
