#ifndef PETTYCOIN_WELCOME_H
#define PETTYCOIN_WELCOME_H
#include "config.h"
#include "protocol_net.h"
#include <ccan/tal/tal.h>

struct state;
struct protocol_pkt_welcome *make_welcome(const tal_t *ctx,
					  const struct state *state,
					  const struct protocol_net_address *a);

enum protocol_ecode check_welcome(const struct peer *peer,
				  const struct protocol_pkt_welcome *w,
				  const struct protocol_block_header **bhdr,
				  size_t *blen);

#endif /* PETTYCOIN_WELCOME_H */
