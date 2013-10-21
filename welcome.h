#ifndef PETTYCOIN_WELCOME_H
#define PETTYCOIN_WELCOME_H
#include <ccan/tal/tal.h>

struct protocol_net_address;
struct state;
struct protocol_req_welcome *make_welcome(const tal_t *ctx,
					  const struct state *state,
					  const struct protocol_net_address *a);

bool check_welcome(const struct protocol_req_welcome *welcome);

#endif /* PETTYCOIN_WELCOME_H */
