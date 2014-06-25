#ifndef PETTYCOIN_TX_CMP_H
#define PETTYCOIN_TX_CMP_H
#include <stdbool.h>
#include <stddef.h>

union protocol_tx;
int tx_cmp(const union protocol_tx *a, const union protocol_tx *b);

static inline int tx_ptr_cmp(union protocol_tx *const *a,
			     union protocol_tx *const *b,
			     void *unused)
{
	return tx_cmp(*a, *b);
}

#endif /* PETTYCOIN_TX_CMP_H */
