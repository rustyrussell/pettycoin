#ifndef PETTYCOIN_PACKET_H
#define PETTYCOIN_PACKET_H
#include <ccan/io/io.h>
#include <ccan/tal/tal.h>
#include <ccan/short_types/short_types.h>

/* All packets are "le32 len, type" then len bytes. */
struct peer;
struct block;

/* Takes any pointer to pointer, fills it in. */
#define io_read_packet(ppkt, cb, arg)					\
	((void)sizeof(**(ppkt)),					\
	 io_read_packet_(ppkt,						\
			 typesafe_cb_preargs(struct io_plan, void *,	\
					     (cb), (arg),		\
					     struct io_conn *),		\
			 (arg)))

struct io_plan io_read_packet_(void *ppkt,
			       struct io_plan (*cb)(struct io_conn *, void *),
			       void *arg);

#define io_write_packet(peer, pkt, next)				\
	io_write_packet_((peer), (pkt),					\
			 typesafe_cb_preargs(struct io_plan, void *,	\
					     (next), (peer),		\
					     struct io_conn *))

/* Frees pkt on next write! */
struct io_plan io_write_packet_(struct peer *peer, const void *pkt,
				struct io_plan (*next)(struct io_conn *,
						       void *));

#define tal_packet(ctx, type, enumtype) \
	((type *)tal_packet_((ctx), sizeof(type), (enumtype)))

void *tal_packet_(const tal_t *ctx, size_t len, int type);

void *tal_packet_dup(const tal_t *ctx, const void *pkt);

/* Make sure they hand &p to these functions! */
#define ptr_to_ptr(p) ((p) + 0*sizeof(**p))
#define tal_packet_append(ppkt, mem, len) \
	tal_packet_append_(ptr_to_ptr(ppkt), (mem), (len))
#define tal_packet_append_trans(ppkt, trans) \
	tal_packet_append_trans_(ptr_to_ptr(ppkt), (trans))
#define tal_packet_append_trans_with_refs(ppkt, trans, refs)		\
	tal_packet_append_trans_with_refs_(ptr_to_ptr(ppkt), (trans), (refs))
#define tal_packet_append_block(ppkt, block)		\
	tal_packet_append_block_(ptr_to_ptr(ppkt), (block))
#define tal_packet_append_sha(ppkt, sha)		\
	tal_packet_append_sha_(ptr_to_ptr(ppkt), (sha))
#define tal_packet_append_proof(ppkt, block, txnum)			\
	tal_packet_append_proof_(ptr_to_ptr(ppkt), (block), (txnum))

union protocol_transaction;
void tal_packet_append_trans_(void *ppkt,
			      const union protocol_transaction *trans);
struct protocol_input_ref;
void tal_packet_append_trans_with_refs_(void *ppkt,
					const union protocol_transaction *trans,
				       const struct protocol_input_ref *refs);

void tal_packet_append_(void *ppkt, const void *mem, size_t len);

void tal_packet_append_block_(void *ppkt, const struct block *block);

struct protocol_double_sha;
void tal_packet_append_sha_(void *ppkt, const struct protocol_double_sha *sha);

void tal_packet_append_proof_(void *ppkt, const struct block *block, u32 txnum);

#endif
