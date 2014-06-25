#ifndef PETTYCOIN_CHECK_TRANSACTION_H
#define PETTYCOIN_CHECK_TRANSACTION_H
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include "protocol_net.h"

struct state;
union protocol_transaction;
struct protocol_transaction_normal;
struct protocol_transaction_gateway;
struct protocol_proof;
struct protocol_address;
struct block;

enum protocol_error
check_trans_normal_basic(struct state *state,
			 const struct protocol_transaction_normal *t);

enum protocol_error
check_trans_from_gateway(struct state *state,
			 const struct block *block,
			 const struct protocol_transaction_gateway *t);

/* True if OK. */
bool check_transaction_proof(struct state *state,
			     union protocol_transaction **trans,
			     struct protocol_proof *proof);

enum protocol_error check_transaction(struct state *state,
				      const union protocol_transaction *trans,
				      const struct block *block,
				      const struct protocol_input_ref *refs,
				      union protocol_transaction *
				      inputs[TRANSACTION_MAX_INPUTS],
				      unsigned int *bad_input_num);

#endif /* PETTYCOIN_CHECK_TRANSACTION_H */
