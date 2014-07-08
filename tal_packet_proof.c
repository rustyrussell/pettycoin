#include "tal_packet_proof.h"
#include "block.h"
#include "proof.h"
#include "packet.h"

void tal_packet_append_proof_(void *ppkt, const struct block *block,
			      u16 shardnum, u8 txoff)
{
	struct protocol_proof proof;

	create_proof(&proof, block, shardnum, txoff);

	tal_packet_append_pos_(ppkt, block, shardnum, txoff);
	tal_packet_append_(ppkt, &proof, sizeof(proof));
	tal_packet_append_tx_with_refs_(ppkt,
					block_get_tx(block, shardnum, txoff),
					block_get_refs(block, shardnum, txoff));
}
