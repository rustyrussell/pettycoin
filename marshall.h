#ifndef PETTYCOIN_MARSHALL_H
#define PETTYCOIN_MARSHALL_H
#include <ccan/tal/tal.h>
#include "protocol_net.h"

/* FIXME: This got ugly fast :(  Rewrite in terms of pull and push-styl
 * primitives. */
struct log;

/* Unmarshall block from wire transfer. */
enum protocol_ecode
unmarshall_block(struct log *log,
		 const struct protocol_pkt_block *pkt,
		 const struct protocol_block_header **hdr,
		 const u8 **shard_nums,
		 const struct protocol_double_sha **merkles,
		 const u8 **prev_merkles,
		 const struct protocol_block_tailer **tailer);

/* Does version and simple sanity checks. */
enum protocol_ecode
unmarshall_block_into(struct log *log,
		      size_t size, const struct protocol_block_header *hdr,
		      const u8 **shard_nums,
		      const struct protocol_double_sha **merkles,
		      const u8 **prev_merkles,
		      const struct protocol_block_tailer **tailer);

/* Marshall block for wire transfer. */
struct protocol_pkt_block *
marshall_block(const tal_t *ctx,
	       const struct protocol_block_header *hdr,
	       const u8 *shard_nums,
	       const struct protocol_double_sha *merkles,
	       const u8 *prev_merkles,
	       const struct protocol_block_tailer *tailer);

/* How long is this block when marshalled? */
size_t marshall_block_len(const struct protocol_block_header *hdr);

/* Store block into dst, which must be at least marshall_block_len. */
void marshall_block_into(void *dst,
			 const struct protocol_block_header *hdr,
			 const u8 *shard_nums,
			 const struct protocol_double_sha *merkles,
			 const u8 *prev_merkles,
			 const struct protocol_block_tailer *tailer);

/* Unmarshall transaction: does version and simple sanity checking. */
enum protocol_ecode unmarshall_tx(const void *buffer, size_t size,
				  size_t *used);

/* Transactions don't need marshalling. */
size_t marshall_tx_len(const union protocol_tx *tx);

enum protocol_ecode unmarshall_input_refs(const void *buffer, size_t size,
					  const union protocol_tx *tx,
					  size_t *used);
/* Input refs don't need marshalling */
size_t marshall_input_ref_len(const union protocol_tx *tx);

#endif /* PETTYCOIN_MARSHALL_H */
