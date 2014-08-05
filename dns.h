#ifndef PETTYCOIN_DNS_H
#define PETTYCOIN_DNS_H
#include "config.h"
#include <ccan/io/io.h>
#include <ccan/tal/tal.h>
#include <stdbool.h>

struct state;
struct protocol_net_address;
tal_t *dns_resolve_and_connect(struct state *state,
			       const char *name, const char *port,
			       struct io_plan *(*init)(struct io_conn *,
						       struct state *,
						       struct protocol_net_address *));

#endif /* PETTYCOIN_DNS_H */
