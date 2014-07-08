/* FIXME: rename to tal_packet */
#ifndef PETTYCOIN_PACKET_H
#define PETTYCOIN_PACKET_H
#include <ccan/tal/tal.h>
#include <ccan/short_types/short_types.h>

#define tal_packet(ctx, type, enumtype) \
	((type *)tal_packet_((ctx), sizeof(type), (enumtype)))

void *tal_packet_(const tal_t *ctx, size_t len, int type);

void *tal_packet_dup(const tal_t *ctx, const void *pkt);

/* Make sure they hand &p to these functions! */
#define ptr_to_ptr(p) ((p) + 0*sizeof(**p))
#define tal_packet_append(ppkt, mem, len) \
	tal_packet_append_(ptr_to_ptr(ppkt), (mem), (len))
#define tal_packet_append_tx(ppkt, tx) \
	tal_packet_append_tx_(ptr_to_ptr(ppkt), (tx))
#define tal_packet_append_tx_with_refs(ppkt, tx, refs)		\
	tal_packet_append_tx_with_refs_(ptr_to_ptr(ppkt), (tx), (refs))
#define tal_packet_append_block(ppkt, block)		\
	tal_packet_append_block_(ptr_to_ptr(ppkt), (block))
#define tal_packet_append_sha(ppkt, sha)		\
	tal_packet_append_sha_(ptr_to_ptr(ppkt), (sha))
#define tal_packet_append_txrefhash(ppkt, hashes)		\
	tal_packet_append_txrefhash_(ptr_to_ptr(ppkt), (hashes))
#define tal_packet_append_pos(ppkt, block, shard, txoff)		\
	tal_packet_append_pos_(ptr_to_ptr(ppkt), (block), (shard), (txoff))

union protocol_tx;
void tal_packet_append_tx_(void *ppkt, const union protocol_tx *tx);
struct protocol_input_ref;
void tal_packet_append_tx_with_refs_(void *ppkt,
				     const union protocol_tx *tx,
				     const struct protocol_input_ref *refs);

void tal_packet_append_(void *ppkt, const void *mem, size_t len);

struct block;
void tal_packet_append_block_(void *ppkt, const struct block *block);

struct protocol_double_sha;
void tal_packet_append_sha_(void *ppkt, const struct protocol_double_sha *sha);

struct protocol_net_txrefhash;
void tal_packet_append_txrefhash_(void *ppkt,
				  const struct protocol_net_txrefhash *hashes);

void tal_packet_append_pos_(void *ppkt, const struct block *block,
			    u16 shardnum, u8 txoff);
#endif
