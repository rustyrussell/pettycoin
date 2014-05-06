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

/* Find the output_num'th output in trans */
bool find_output(union protocol_transaction *trans, u16 output_num,
		 struct protocol_address *addr, u32 *amount);

/* Only normal transactions have inputs; 0 for others. */
static inline u32 num_inputs(const union protocol_transaction *t)
{
	switch (t->hdr.type) {
	case TRANSACTION_NORMAL:
		return le32_to_cpu(t->normal.num_inputs);
	case TRANSACTION_FROM_GATEWAY:
		return 0;
	}
	abort();
}
#endif /* PETTYCOIN_CHECK_TRANSACTION_H */
