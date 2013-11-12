#ifndef PETTYCOIN_MARSHALL_H
#define PETTYCOIN_MARSHALL_H
#include <ccan/tal/tal.h>
#include "protocol_net.h"

/* Does version and simple sanity checks. */
struct protocol_block_header *
unmarshall_block(struct protocol_req_new_block *buffer,
		 struct protocol_double_sha **merkles,
		 u8 **prev_merkles,
		 struct protocol_block_tailer **tailer);

/* Marhsall block for wire transfer. */
struct protocol_req_new_block *
marshall_block(const tal_t *ctx,
	       const struct protocol_block_header *hdr,
	       const struct protocol_double_sha *merkles,
	       const u8 *prev_merkles,
	       const struct protocol_block_tailer *tailer);

/* Unmarshall transaction: does version and simple sanity checking. */
union protocol_transaction *unmarshall_transaction(void *buffer, size_t size);

/* Transactions don't need marshalling. */
size_t marshall_transaction_len(const union protocol_transaction *t);

#endif /* PETTYCOIN_MARSHALL_H */
