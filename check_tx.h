#ifndef PETTYCOIN_CHECK_TX_H
#define PETTYCOIN_CHECK_TX_H
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include "protocol_net.h"

struct state;
union protocol_tx;
struct protocol_tx_normal;
struct protocol_tx_gateway;
struct protocol_proof;
struct protocol_address;
struct block;

enum protocol_ecode
check_tx_normal_basic(struct state *state,
			 const struct protocol_tx_normal *ntx);

enum protocol_ecode
check_tx_from_gateway(struct state *state,
		      const struct block *block,
		      const struct protocol_tx_gateway *gtx);

enum protocol_ecode check_tx(struct state *state,
			     const union protocol_tx *trans,
			     const struct block *block,
			     const struct protocol_input_ref *refs,
			     union protocol_tx *inputs[PROTOCOL_TX_MAX_INPUTS],
			     unsigned int *bad_input_num);

#endif /* PETTYCOIN_CHECK_TX_H */
