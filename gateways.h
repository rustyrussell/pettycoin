#ifndef PETTYCOIN_GATEWAYS_H
#define PETTYCOIN_GATEWAYS_H
#include "config.h"
#include <stdbool.h>

struct state;
struct protocol_address;
bool accept_gateway(const struct state *state,
		    const struct protocol_address *addr);

#endif /* PETTYCOIN_GATEWAYS_H */
