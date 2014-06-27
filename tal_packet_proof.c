#include "tal_packet_proof.h"
#include "block.h"
#include "proof.h"
#include "packet.h"

void tal_packet_append_proof_(void *ppkt, const struct block *block,
			      u16 shardnum, u8 txoff)
{
	struct protocol_tx_with_proof proof;

	proof.block = block->sha;
	proof.shard = cpu_to_le16(shardnum);
	proof.txoff = txoff;
	proof.unused = 0;
	create_proof(&proof.proof, block, shardnum, txoff);

	tal_packet_append_(ppkt, &proof, sizeof(proof));
	tal_packet_append_tx_with_refs_(ppkt,
					block_get_tx(block, shardnum, txoff),
					block_get_refs(block, shardnum, txoff));
}
