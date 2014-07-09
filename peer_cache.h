#ifndef PETTYCOIN_PEER_CACHE_H
#define PETTYCOIN_PEER_CACHE_H
#include "config.h"
#include <ccan/short_types/short_types.h>
#include <stdbool.h>

struct state;
struct protocol_net_address;

void fill_peers(struct state *state);
void init_peer_cache(struct state *state);

void peer_cache_add(struct state *state, 
		    const struct protocol_net_address *addr);
void peer_cache_update(struct state *state, 
		       const struct protocol_net_address *addr,
		       u32 last_used);
struct protocol_net_address *read_peer_cache(struct state *state);
void peer_cache_del(struct state *state,
		    const struct protocol_net_address *addr,
		    bool del_on_disk);
#endif /* PETTYCOIN_PEER_CACHE_H */
