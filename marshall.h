#ifndef PETTYCOIN_MARSHALL_H
#define PETTYCOIN_MARSHALL_H
#include <ccan/tal/tal.h>
#include "protocol_net.h"

/* FIXME: This got ugly fast :(  Rewrite in terms of pull and push-styl
 * primitives. */
struct log;

/* Does version and simple sanity checks. */
enum protocol_error
unmarshall_block(struct log *log,
		 size_t size, const struct protocol_block_header *hdr,
		 const struct protocol_double_sha **merkles,
		 const u8 **prev_merkles,
		 const struct protocol_block_tailer **tailer);

/* Marshall block for wire transfer. */
struct protocol_req_new_block *
marshall_block(const tal_t *ctx,
	       const struct protocol_block_header *hdr,
	       const struct protocol_double_sha *merkles,
	       const u8 *prev_merkles,
	       const struct protocol_block_tailer *tailer);

/* Unmarshall transaction: does version and simple sanity checking. */
enum protocol_error unmarshall_transaction(const void *buffer, size_t size,
					   size_t *used);

/* Transactions don't need marshalling. */
size_t marshall_transaction_len(const union protocol_transaction *t);

#endif /* PETTYCOIN_MARSHALL_H */
