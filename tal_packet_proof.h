#ifndef PETTYCOIN_TAL_PACKET_APPEND_PROOF_H
#define PETTYCOIN_TAL_PACKET_APPEND_PROOF_H
/* Generate wants packet.o, but this function pulls in too much. */
#include "block.h"

#define tal_packet_append_proof(ppkt, block, shardnum, txidx)		\
	tal_packet_append_proof_(ptr_to_ptr(ppkt), (block), (shardnum), (txidx))

void tal_packet_append_proof_(void *ppkt, const struct block *block,
			      u16 shardnum, u8 txoff);
#endif /* PETTYCOIN_TAL_PACKET_APPEND_PROOF_H */
