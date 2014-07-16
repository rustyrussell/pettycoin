#ifndef PETTYCOIN_CHECK_TX_H
#define PETTYCOIN_CHECK_TX_H
#include "config.h"
#include "protocol_net.h"
#include "txhash.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>

struct state;
union protocol_tx;
struct protocol_tx_normal;
struct protocol_tx_gateway;
struct protocol_proof;
struct protocol_address;
struct block;
struct txhash_elem;

/* After this, call check_tx_inputs! 
 * inside_block is what block the tx is in (can be NULL).
 */
enum protocol_ecode check_tx(struct state *state, const union protocol_tx *tx,
			     const struct block *inside_block);

enum input_ecode {
	ECODE_INPUT_OK,
	ECODE_INPUT_UNKNOWN,
	ECODE_INPUT_BAD,
	ECODE_INPUT_BAD_AMOUNT,
	ECODE_INPUT_DOUBLESPEND,
	ECODE_INPUT_CLAIM_BAD
};

/* Note that this won't resolve inputs which are pending: you'll get
 * ECODE_INPUT_UNKNOWN and must resolve yourself. */
enum input_ecode check_tx_inputs(struct state *state,
				 const struct block *block,
				 const struct txhash_elem *me,
				 const union protocol_tx *tx,
				 unsigned int *bad_input_num);

/* Useful for checking complaints (not for TX_CLAIM txs). */
enum input_ecode check_simple_input(struct state *state,
				    const struct protocol_input *inp,
				    const union protocol_tx *intx,
				    const struct protocol_address *my_addr,
				    u32 *amount);

/* Gets result if above return ECODE_INPUT_DOUBLESPEND. */
struct txhash_elem *tx_find_doublespend(struct state *state,
					const struct block *block,
					const struct txhash_elem *me,
					const struct protocol_input *inp);
#endif /* PETTYCOIN_CHECK_TX_H */
