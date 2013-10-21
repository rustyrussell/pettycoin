#ifndef PETTYCOIN_DNS_H
#define PETTYCOIN_DNS_H
#include <ccan/io/io.h>
#include <stdbool.h>

struct state;
bool dns_resolve_and_connect(struct state *state,
			     const char *name, const char *port,
			     struct io_plan (*init)(struct io_conn *,
						    struct state *));

#endif /* PETTYCOIN_DNS_H */
