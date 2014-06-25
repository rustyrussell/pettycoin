#include <ccan/endian/endian.h>
#include <ccan/build_assert/build_assert.h>
#include "marshall.h"
#include "protocol_net.h"
#include "overflows.h"
#include "block.h"
#include "check_transaction.h"
#include "version.h"
#include "talv.h"
#include "peer.h"
#include "log.h"
#include <assert.h>

enum protocol_error
unmarshall_block_into(struct log *log,
		      size_t size, const struct protocol_block_header *hdr,
		      const u8 **shard_nums,
		      const struct protocol_double_sha **merkles,
		      const u8 **prev_merkles,
		      const struct protocol_block_tailer **tailer)
{
	size_t len, merkle_len, shard_len;

	if (size < sizeof(*hdr)) {
		log_unusual(log, "total size %zu < header size %zu",
			    size, sizeof(*hdr));
		return PROTOCOL_INVALID_LEN;
	}

	if (!version_ok(hdr->version)) {
		log_unusual(log, "version %u not OK", hdr->version);
		return PROTOCOL_ERROR_BLOCK_HIGH_VERSION;
	}

	/* Make sure we can't ever overflow when we sum transactions. */
	BUILD_ASSERT(PROTOCOL_MAX_SHARD_ORDER < 24);

	if (hdr->shard_order > PROTOCOL_MAX_SHARD_ORDER) {
		log_unusual(log, "shard_order %u not OK", hdr->shard_order);
		return PROTOCOL_ERROR_BAD_SHARD_ORDER;
	}
	len = sizeof(*hdr);

	/* Shards come next. */
	*shard_nums = (u8 *)(hdr + 1);

	shard_len = 1 << hdr->shard_order;
	if (add_overflows(shard_len, len)) {
		log_unusual(log, "shard_len %zu overflows", shard_len);
		return PROTOCOL_INVALID_LEN;
	}
	len += shard_len;

	/* Merkles come after shard numbers. */
	*merkles = (struct protocol_double_sha *)(*shard_nums + shard_len);

	/* This can't actually happen, but be thorough. */
	if (mul_overflows(shard_len, sizeof(struct protocol_double_sha))) {
		log_unusual(log, "merkle_len %zu overflows", shard_len);
		return PROTOCOL_INVALID_LEN;
	}
	merkle_len = shard_len * sizeof(struct protocol_double_sha);

	if (add_overflows(len, merkle_len)) {
		log_unusual(log, "len %zu + merkle_len %zu overflows",
			    len, merkle_len);
		return PROTOCOL_INVALID_LEN;
	}

	len += merkle_len;

	/* Next comes prev_merkles. */
	*prev_merkles = (u8 *)hdr + len;
	if (add_overflows(len, le32_to_cpu(hdr->num_prev_merkles))) {
		log_unusual(log, "len %zu + prev_merkles %u overflows",
			    len, le32_to_cpu(hdr->num_prev_merkles));
		return PROTOCOL_INVALID_LEN;
	}
	len += le32_to_cpu(hdr->num_prev_merkles);

	/* Finally comes tailer. */
	*tailer = (struct protocol_block_tailer *)
		(*prev_merkles + le32_to_cpu(hdr->num_prev_merkles));

	if (add_overflows(len, sizeof(**tailer))) {
		log_unusual(log, "len %zu + tailer %zu overflows",
			    len, sizeof(**tailer));
		return PROTOCOL_INVALID_LEN;
	}

	len += sizeof(**tailer);

	/* Size must be exactly right. */
	if (size != len) {
		log_unusual(log, "len %zu is not expected len %zu", size, len);
		return PROTOCOL_INVALID_LEN;
	}

	log_debug(log, "unmarshalled block size %zu", size);
	return PROTOCOL_ERROR_NONE;
}

enum protocol_error
unmarshall_block(struct log *log,
		 const struct protocol_pkt_block *pkt,
		 const struct protocol_block_header **hdr,
		 const u8 **shard_nums,
		 const struct protocol_double_sha **merkles,
		 const u8 **prev_merkles,
		 const struct protocol_block_tailer **tailer)
{
	*hdr = (void *)(pkt + 1);
	return unmarshall_block_into(log, le32_to_cpu(pkt->len) - sizeof(*pkt),
				     *hdr, shard_nums, merkles, prev_merkles,
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
	*prev_merkle_len = sizeof(u8) * le32_to_cpu(hdr->num_prev_merkles);

	return sizeof(*hdr) + *shardnum_len + *merkle_len + *prev_merkle_len
		+ sizeof(struct protocol_block_tailer);
}

size_t marshall_block_len(const struct protocol_block_header *hdr)
{
	size_t shardnum_len, merkle_len, prev_merkle_len;

	return block_lengths(hdr, &shardnum_len, &merkle_len, &prev_merkle_len);
}

void marshall_block_into(void *dst,
			 const struct protocol_block_header *hdr,
			 const u8 *shard_nums,
			 const struct protocol_double_sha *merkles,
			 const u8 *prev_merkles,
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
	memcpy(dest, prev_merkles, prev_merkle_len);
	dest += prev_merkle_len;
	memcpy(dest, tailer, sizeof(*tailer));
}

struct protocol_pkt_block *
marshall_block(const tal_t *ctx,
	       const struct protocol_block_header *hdr,
	       const u8 *shard_nums,
	       const struct protocol_double_sha *merkles,
	       const u8 *prev_merkles,
	       const struct protocol_block_tailer *tailer)
{
	struct protocol_pkt_block *ret;
	size_t len;

	len = marshall_block_len(hdr);
	ret = (void *)tal_arr(ctx, char, sizeof(*ret) + len);

	ret->len = cpu_to_le32(sizeof(*ret) + len);
	ret->type = cpu_to_le32(PROTOCOL_PKT_BLOCK);

	marshall_block_into(ret + 1,
			    hdr, shard_nums, merkles, prev_merkles, tailer);
	return ret;
}

/* Make sure transaction is all there. */
enum protocol_error unmarshall_transaction(const void *buffer, size_t size,
					   size_t *used)
{
	const union protocol_transaction *t = buffer;
	size_t i, len;

	if (size < sizeof(t->hdr))
		return PROTOCOL_INVALID_LEN;

	if (!version_ok(t->hdr.version))
		return PROTOCOL_ERROR_TRANS_HIGH_VERSION;

	switch (t->hdr.type) {
	case TRANSACTION_NORMAL:
		if (size < sizeof(t->normal))
			return PROTOCOL_INVALID_LEN;
		if (mul_overflows(sizeof(t->normal.input[0]),
				  le32_to_cpu(t->normal.num_inputs)))
			return PROTOCOL_INVALID_LEN;
		i = sizeof(t->normal.input[0])
			* le32_to_cpu(t->normal.num_inputs);

		if (add_overflows(sizeof(t->normal), i))
			return PROTOCOL_INVALID_LEN;
		len = sizeof(t->normal) + i;
		break;
	case TRANSACTION_FROM_GATEWAY:
		if (size < sizeof(t->gateway))
			return PROTOCOL_INVALID_LEN;
		
		if (mul_overflows(sizeof(t->gateway.output[0]),
				  le16_to_cpu(t->gateway.num_outputs)))
			return PROTOCOL_INVALID_LEN;
		i = sizeof(t->gateway.output[0])
			* le16_to_cpu(t->gateway.num_outputs);

		if (add_overflows(sizeof(t->gateway), i))
			return PROTOCOL_INVALID_LEN;

		len = sizeof(t->gateway) + i;
		break;
	default:
		/* Unknown type. */
		return PROTOCOL_ERROR_TRANS_UNKNOWN;
	}

	if (size < len)
		return PROTOCOL_INVALID_LEN;

	/* If caller expects a remainder, that's OK, otherwise an error. */
	if (used)
		*used = len;
	else if (size != len)
		return PROTOCOL_INVALID_LEN;

	return PROTOCOL_ERROR_NONE;
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

#define varsize(type, field, num)				\
	varsize_(sizeof(type), (num), sizeof(((type *)0)->field[0]))

/* Returns 0 on length overflow! */
size_t marshall_transaction_len(const union protocol_transaction *t)
{
	switch (t->hdr.type) {
	case TRANSACTION_NORMAL:
		return varsize(struct protocol_transaction_normal,
			       input, le32_to_cpu(t->normal.num_inputs));
	case TRANSACTION_FROM_GATEWAY:
		return varsize(struct protocol_transaction_gateway,
			       output, le16_to_cpu(t->gateway.num_outputs));
	}
	abort();
}

enum protocol_error unmarshall_input_refs(const void *buffer, size_t size,
					  const union protocol_transaction *t,
					  size_t *used)
{
	size_t need = marshall_input_ref_len(t);

	if (size < need)
		return PROTOCOL_INVALID_LEN;
	
	*used = need;
	return PROTOCOL_ERROR_NONE;
}

/* Input refs don't need marshalling */
size_t marshall_input_ref_len(const union protocol_transaction *t)
{
	return num_inputs(t) * sizeof(struct protocol_input_ref);
}
