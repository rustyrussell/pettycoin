#ifndef PETTYCOIN_WELCOME_H
#define PETTYCOIN_WELCOME_H
#include <ccan/tal/tal.h>
#include "protocol_net.h"

struct state;
struct protocol_req_welcome *make_welcome(const tal_t *ctx,
					  const struct state *state,
					  const struct protocol_net_address *a);

enum protocol_error check_welcome(const struct state *state,
				  const struct protocol_req_welcome *w);

#endif /* PETTYCOIN_WELCOME_H */
