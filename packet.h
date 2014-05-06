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

union protocol_transaction;
void tal_packet_append_trans(void *ppkt,
			     const union protocol_transaction *trans);
struct protocol_input_ref;
void tal_packet_append_trans_with_refs(void *ppkt,
				       const union protocol_transaction *trans,
				       const struct protocol_input_ref *refs);

void tal_packet_append(void *ppkt, const void *mem, size_t len);

void tal_packet_append_proof(void *ppkt, const struct block *block, u32 txnum);

#endif
