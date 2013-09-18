#ifndef PETTYCOIN_TRANSACTION_CMP_H
#define PETTYCOIN_TRANSACTION_CMP_H
#include <stdbool.h>
#include <stddef.h>

union protocol_transaction;
int transaction_cmp(const union protocol_transaction *a,
		    const union protocol_transaction *b);

static inline int transaction_ptr_cmp(union protocol_transaction *const *a,
				      union protocol_transaction *const *b,
				      void *unused)
{
	return transaction_cmp(*a, *b);
}

#endif /* PETTYCOIN_TRANSACTION_CMP_H */
