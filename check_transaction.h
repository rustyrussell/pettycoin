#ifndef PETTYCOIN_CHECK_TRANSACTION_H
#define PETTYCOIN_CHECK_TRANSACTION_H
#include <stdbool.h>
#include <ccan/short_types/short_types.h>
#include <stddef.h>

struct state;
union protocol_transaction;
struct protocol_proof;
struct protocol_address;

/* True if OK. */
bool check_transaction(struct state *state,
		       union protocol_transaction **trans,
		       struct protocol_proof *proof);

/* Find the output_num'th output in trans */
bool find_output(union protocol_transaction *trans, u16 output_num,
		 struct protocol_address *addr, u32 *amount);

union protocol_transaction *unmarshall_transaction(void *buffer, size_t size);

#endif /* PETTYCOIN_CHECK_TRANSACTION_H */
