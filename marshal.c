#include "block.h"
#include "log.h"
#include "marshal.h"
#include "overflows.h"
#include "peer.h"
#include "protocol_net.h"
#include "tx.h"
#include "version.h"
#include <assert.h>
#include <ccan/build_assert/build_assert.h>
#include <ccan/endian/endian.h>

enum protocol_ecode
unmarshal_block_into(struct log *log,
		     size_t size, const struct protocol_block_header *hdr,
		     const u8 **shard_nums,
		     const struct protocol_double_sha **merkles,
		     const u8 **prev_txhashes,
		     const struct protocol_block_tailer **tailer)
{
	size_t len, merkle_len, shard_len;

	if (size < sizeof(*hdr)) {
		log_unusual(log, "total size %zu < header size %zu",
			    size, sizeof(*hdr));
		return PROTOCOL_ECODE_INVALID_LEN;
	}

	if (!version_ok(hdr->version)) {
		log_unusual(log, "version %u not OK", hdr->version);
		return PROTOCOL_ECODE_BLOCK_HIGH_VERSION;
	}

	/* Make sure we can't ever overflow when we sum transactions. */
	BUILD_ASSERT(PROTOCOL_MAX_SHARD_ORDER < 24);

	if (hdr->shard_order > PROTOCOL_MAX_SHARD_ORDER) {
		log_unusual(log, "shard_order %u not OK", hdr->shard_order);
		return PROTOCOL_ECODE_BAD_SHARD_ORDER;
	}
	len = sizeof(*hdr);

	/* Shards come next. */
	*shard_nums = (u8 *)(hdr + 1);

	shard_len = 1 << hdr->shard_order;
	if (add_overflows(shard_len, len)) {
		log_unusual(log, "shard_len %zu overflows", shard_len);
		return PROTOCOL_ECODE_INVALID_LEN;
	}
	len += shard_len;

	/* Merkles come after shard numbers. */
	*merkles = (struct protocol_double_sha *)(*shard_nums + shard_len);

	/* This can't actually happen, but be thorough. */
	if (mul_overflows(shard_len, sizeof(struct protocol_double_sha))) {
		log_unusual(log, "merkle_len %zu overflows", shard_len);
		return PROTOCOL_ECODE_INVALID_LEN;
	}
	merkle_len = shard_len * sizeof(struct protocol_double_sha);

	if (add_overflows(len, merkle_len)) {
		log_unusual(log, "len %zu + merkle_len %zu overflows",
			    len, merkle_len);
		return PROTOCOL_ECODE_INVALID_LEN;
	}

	len += merkle_len;

	/* Next comes prev_txhashes. */
	*prev_txhashes = (u8 *)hdr + len;
	if (add_overflows(len, le32_to_cpu(hdr->num_prev_txhashes))) {
		log_unusual(log, "len %zu + prev_txhashes %u overflows",
			    len, le32_to_cpu(hdr->num_prev_txhashes));
		return PROTOCOL_ECODE_INVALID_LEN;
	}
	len += le32_to_cpu(hdr->num_prev_txhashes);

	/* Finally comes tailer. */
	*tailer = (struct protocol_block_tailer *)
		(*prev_txhashes + le32_to_cpu(hdr->num_prev_txhashes));

	if (add_overflows(len, sizeof(**tailer))) {
		log_unusual(log, "len %zu + tailer %zu overflows",
			    len, sizeof(**tailer));
		return PROTOCOL_ECODE_INVALID_LEN;
	}

	len += sizeof(**tailer);

	/* Size must be exactly right. */
	if (size != len) {
		log_unusual(log, "len %zu is not expected len %zu", size, len);
		return PROTOCOL_ECODE_INVALID_LEN;
	}

	log_debug(log, "unmarshaled block size %zu", size);
	return PROTOCOL_ECODE_NONE;
}

enum protocol_ecode
unmarshal_block(struct log *log,
		const struct protocol_pkt_block *pkt,
		const struct protocol_block_header **hdr,
		const u8 **shard_nums,
		const struct protocol_double_sha **merkles,
		const u8 **prev_txhashes,
		const struct protocol_block_tailer **tailer)
{
	*hdr = (void *)(pkt + 1);
	return unmarshal_block_into(log, le32_to_cpu(pkt->len) - sizeof(*pkt),
				     *hdr, shard_nums, merkles, prev_txhashes,
				     tailer);
}

/* Returns total length, sets shardnum_len, merkle_len, prev_merkle_len */
static size_t block_lengths(const struct protocol_block_header *hdr,
			    size_t *shardnum_len,
			    size_t *merkle_len, size_t *prev_merkle_len)
{
	u32 num_shards = (u32)1 << hdr->shard_order;
	*shardnum_len = num_shards * sizeof(u8);
	*merkle_len = sizeof(struct protocol_double_sha) * num_shards;
	*prev_merkle_len = sizeof(u8) * le32_to_cpu(hdr->num_prev_txhashes);

	return sizeof(*hdr) + *shardnum_len + *merkle_len + *prev_merkle_len
		+ sizeof(struct protocol_block_tailer);
}

size_t marshal_block_len(const struct protocol_block_header *hdr)
{
	size_t shardnum_len, merkle_len, prev_merkle_len;

	return block_lengths(hdr, &shardnum_len, &merkle_len, &prev_merkle_len);
}

void marshal_block_into(void *dst,
			const struct protocol_block_header *hdr,
			const u8 *shard_nums,
			const struct protocol_double_sha *merkles,
			const u8 *prev_txhashes,
			const struct protocol_block_tailer *tailer)
{
	char *dest = dst;
	size_t shardnum_len, merkle_len, prev_merkle_len;

	block_lengths(hdr, &shardnum_len, &merkle_len, &prev_merkle_len);

	memcpy(dest, hdr, sizeof(*hdr));
	dest += sizeof(*hdr);
	memcpy(dest, shard_nums, shardnum_len);
	dest += shardnum_len;
	memcpy(dest, merkles, merkle_len);
	dest += merkle_len;
	memcpy(dest, prev_txhashes, prev_merkle_len);
	dest += prev_merkle_len;
	memcpy(dest, tailer, sizeof(*tailer));
}

struct protocol_pkt_block *
marshal_block(const tal_t *ctx,
	      const struct protocol_block_header *hdr,
	      const u8 *shard_nums,
	      const struct protocol_double_sha *merkles,
	      const u8 *prev_txhashes,
	      const struct protocol_block_tailer *tailer)
{
	struct protocol_pkt_block *ret;
	size_t len;

	len = marshal_block_len(hdr);
	ret = (void *)tal_arr(ctx, char, sizeof(*ret) + len);

	ret->len = cpu_to_le32(sizeof(*ret) + len);
	ret->type = cpu_to_le32(PROTOCOL_PKT_BLOCK);
	ret->err = cpu_to_le32(PROTOCOL_ECODE_NONE);

	marshal_block_into(ret + 1,
			    hdr, shard_nums, merkles, prev_txhashes, tailer);
	return ret;
}

/* Make sure transaction is all there. */
enum protocol_ecode unmarshal_tx(const void *buffer, size_t size, size_t *used)
{
	const union protocol_tx *tx = buffer;
	size_t i, len;

	if (size < sizeof(tx->hdr))
		return PROTOCOL_ECODE_INVALID_LEN;

	if (!version_ok(tx->hdr.version))
		return PROTOCOL_ECODE_TX_HIGH_VERSION;

	switch (tx_type(tx)) {
	case TX_NORMAL:
		if (size < sizeof(tx->normal))
			return PROTOCOL_ECODE_INVALID_LEN;
		if (mul_overflows(sizeof(struct protocol_input),
				  le32_to_cpu(tx->normal.num_inputs)))
			return PROTOCOL_ECODE_INVALID_LEN;
		i = sizeof(struct protocol_input)
			* le32_to_cpu(tx->normal.num_inputs);

		if (add_overflows(sizeof(tx->normal), i))
			return PROTOCOL_ECODE_INVALID_LEN;
		len = sizeof(tx->normal) + i;
		goto known;
	case TX_FROM_GATEWAY:
		if (size < sizeof(tx->from_gateway))
			return PROTOCOL_ECODE_INVALID_LEN;
		
		if (mul_overflows(sizeof(struct protocol_gateway_payment),
				  le16_to_cpu(tx->from_gateway.num_outputs)))
			return PROTOCOL_ECODE_INVALID_LEN;
		i = sizeof(struct protocol_gateway_payment)
			* le16_to_cpu(tx->from_gateway.num_outputs);

		if (add_overflows(sizeof(tx->from_gateway), i))
			return PROTOCOL_ECODE_INVALID_LEN;

		len = sizeof(tx->from_gateway) + i;
		goto known;
	case TX_TO_GATEWAY:
		if (size < sizeof(tx->to_gateway))
			return PROTOCOL_ECODE_INVALID_LEN;
		if (mul_overflows(sizeof(struct protocol_input),
				  le32_to_cpu(tx->to_gateway.num_inputs)))
			return PROTOCOL_ECODE_INVALID_LEN;
		i = sizeof(struct protocol_input)
			* le32_to_cpu(tx->to_gateway.num_inputs);

		if (add_overflows(sizeof(tx->to_gateway), i))
			return PROTOCOL_ECODE_INVALID_LEN;
		len = sizeof(tx->to_gateway) + i;
		goto known;
	}

	/* Unknown type. */
	return PROTOCOL_ECODE_TX_TYPE_UNKNOWN;

known:
	if (size < len)
		return PROTOCOL_ECODE_INVALID_LEN;

	/* If caller expects a remainder, that's OK, otherwise an error. */
	if (used)
		*used = len;
	else if (size != len)
		return PROTOCOL_ECODE_INVALID_LEN;

	return PROTOCOL_ECODE_NONE;
}

static size_t varsize_(size_t base, size_t num, size_t fieldsize)
{
	assert(base);

	if (mul_overflows(fieldsize, num))
		return 0;

	if (add_overflows(base, fieldsize * num))
		return 0;

	return base + fieldsize * num;
}

#define varsize(type, extra, num)			\
	varsize_(sizeof(type), (num), sizeof(extra))

/* Returns 0 on length overflow! */
size_t marshal_tx_len(const union protocol_tx *tx)
{
	switch (tx_type(tx)) {
	case TX_NORMAL:
		return varsize(tx->normal, struct protocol_input,
			       le32_to_cpu(tx->normal.num_inputs));
	case TX_FROM_GATEWAY:
		return varsize(tx->from_gateway,
			       struct protocol_gateway_payment,
			       le16_to_cpu(tx->from_gateway.num_outputs));
	case TX_TO_GATEWAY:
		return varsize(tx->to_gateway, struct protocol_input,
			       le32_to_cpu(tx->to_gateway.num_inputs));
	}
	abort();
}

enum protocol_ecode unmarshal_input_refs(const void *buffer, size_t size,
					 const union protocol_tx *tx,
					 size_t *used)
{
	size_t need = marshal_input_ref_len(tx);

	if (size < need)
		return PROTOCOL_ECODE_INVALID_LEN;
	
	*used = need;
	return PROTOCOL_ECODE_NONE;
}

/* Input refs don't need marshaling */
size_t marshal_input_ref_len(const union protocol_tx *tx)
{
	return num_inputs(tx) * sizeof(struct protocol_input_ref);
}
