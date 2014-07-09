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

/* After this, call check_tx_inputs! 
 * inside_block is what block the tx is in (can be NULL).
 */
enum protocol_ecode check_tx(struct state *state, const union protocol_tx *tx,
			     const struct block *inside_block);

enum input_ecode {
	ECODE_INPUT_OK,
	ECODE_INPUT_UNKNOWN,
	ECODE_INPUT_BAD,
	ECODE_INPUT_BAD_AMOUNT
};

enum input_ecode check_tx_inputs(struct state *state,
				 const union protocol_tx *tx,
				 unsigned int *bad_input_num);
#endif /* PETTYCOIN_CHECK_TX_H */
