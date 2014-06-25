#include "packet.h"
#include "protocol.h"
#include "protocol_net.h"
#include "marshall.h"
#include "block.h"
#include "proof.h"
#include <assert.h>

void *tal_packet_(const tal_t *ctx, size_t len, int type)
{
	struct protocol_net_hdr *hdr;

	assert(len >= sizeof(*hdr));
	assert(len < PROTOCOL_MAX_PACKET_LEN);

	/* Must be a char array so that tal_count() is in bytes */
	hdr = (void *)tal_arr(ctx, char, len);

	hdr->len = cpu_to_le32(len);
	hdr->type = cpu_to_le32(type);

	return hdr;
}

void *tal_packet_dup(const tal_t *ctx, const void *pkt)
{
	const struct protocol_net_hdr *hdr = pkt;
	size_t len = le32_to_cpu(hdr->len);

	assert(len >= sizeof(*hdr));
	return tal_dup(ctx, char, (char *)pkt, len, 0);
}

void tal_packet_append_(void *ppkt, const void *mem, size_t len)
{
	struct protocol_net_hdr **hdr = ppkt;
	u32 orig_len = le32_to_cpu((*hdr)->len);

	tal_resize((char **)ppkt, orig_len + len);
	hdr = ppkt;
	memcpy((char *)*hdr + orig_len, mem, len);
	(*hdr)->len = cpu_to_le32(orig_len + len);
}

void tal_packet_append_tx_(void *ppkt, const union protocol_tx *tx)
{
	tal_packet_append_(ppkt, tx, marshall_tx_len(tx));
}

void tal_packet_append_tx_with_refs_(void *ppkt,
				     const union protocol_tx *tx,
				     const struct protocol_input_ref *refs)
{
	tal_packet_append_tx_(ppkt, tx);
	tal_packet_append_(ppkt, refs, marshall_input_ref_len(tx));
}

void tal_packet_append_block_(void *ppkt, const struct block *block)
{
	struct protocol_net_hdr **hdr = ppkt;
	u32 orig_len = le32_to_cpu((*hdr)->len);
	size_t len = marshall_block_len(block->hdr);

	tal_resize((char **)ppkt, orig_len + len);
	hdr = ppkt;
	marshall_block_into((char *)*hdr + orig_len,
			    block->hdr, block->shard_nums, block->merkles,
			    block->prev_merkles, block->tailer);
	(*hdr)->len = cpu_to_le32(orig_len + len);
}

void tal_packet_append_sha_(void *ppkt, const struct protocol_double_sha *sha)
{
	tal_packet_append_(ppkt, sha, sizeof(*sha));
}

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

void tal_packet_append_txrefhash_(void *ppkt,
				  const struct protocol_net_txrefhash *hashes)
{
	tal_packet_append_(ppkt, hashes, sizeof(*hashes));
}
