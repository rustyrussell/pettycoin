#ifndef PETTYCOIN_MARSHAL_H
#define PETTYCOIN_MARSHAL_H
#include "config.h"
#include "protocol_net.h"
#include <ccan/tal/tal.h>

/* FIXME: This got ugly fast :(  Rewrite in terms of pull and push-styl
 * primitives. */
struct log;
struct block_info;

/* Unmarshal block from wire transfer. */
enum protocol_ecode
unmarshal_block(struct log *log,
		const struct protocol_pkt_block *pkt,
		struct block_info *bi);

/* Does version and simple sanity checks. */
enum protocol_ecode
unmarshal_block_into(struct log *log,
		     size_t size, const struct protocol_block_header *hdr,
		     struct block_info *bi);

/* Marshal block for wire transfer. */
struct protocol_pkt_block *
marshal_block(const tal_t *ctx, const struct block_info *bi);

/* How long is this block when marshaled? */
size_t marshal_block_len(const struct protocol_block_header *hdr);

/* Store block into dst, which must be at least marshal_block_len. */
void marshal_block_into(void *dst, const struct block_info *bi);

/* Unmarshal transaction: does version and simple sanity checking. */
enum protocol_ecode unmarshal_tx(const void *buffer, size_t size,
				  size_t *used);

enum protocol_ecode unmarshal_input_refs(const void *buffer, size_t size,
					 const union protocol_tx *tx,
					 size_t *used);
/* Input refs don't need marshaling */
size_t marshal_input_ref_len(const union protocol_tx *tx);

#endif /* PETTYCOIN_MARSHAL_H */
