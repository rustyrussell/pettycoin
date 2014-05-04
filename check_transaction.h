#ifndef PETTYCOIN_CHECK_TRANSACTION_H
#define PETTYCOIN_CHECK_TRANSACTION_H
#include <stdbool.h>
#include <stddef.h>
#include "protocol_net.h"

struct state;
union protocol_transaction;
struct protocol_transaction_normal;
struct protocol_transaction_gateway;
struct protocol_proof;
struct protocol_address;

enum protocol_error
check_trans_normal_basic(struct state *state,
			 const struct protocol_transaction_normal *t);

enum protocol_error
check_trans_normal_inputs(struct state *state,
			  const struct protocol_transaction_normal *t,
			  unsigned int *inputs_known,
			  union protocol_transaction *
			  inputs[TRANSACTION_MAX_INPUTS],
			  unsigned int *bad_input_num);

enum protocol_error
check_trans_from_gateway(struct state *state,
			 const struct protocol_transaction_gateway *t);

/* True if OK. */
bool check_transaction_proof(struct state *state,
			     union protocol_transaction **trans,
			     struct protocol_proof *proof);

/* Only normal transactions have inputs; 0 for others. */
u32 num_inputs(const union protocol_transaction *t);

enum protocol_error check_transaction(struct state *state,
				      const union protocol_transaction *trans,
				      union protocol_transaction *
				      inputs[TRANSACTION_MAX_INPUTS],
				      unsigned int *bad_input_num);

/* Find the output_num'th output in trans */
bool find_output(union protocol_transaction *trans, u16 output_num,
		 struct protocol_address *addr, u32 *amount);

#endif /* PETTYCOIN_CHECK_TRANSACTION_H */
