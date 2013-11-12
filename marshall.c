#include <ccan/endian/endian.h>
#include "marshall.h"
#include "protocol_net.h"
#include "overflows.h"
#include "merkle_transactions.h"
#include "version.h"
#include "talv.h"
#include <assert.h>

struct protocol_block_header *
unmarshall_block(struct protocol_req_new_block *buffer,
		 struct protocol_double_sha **merkles,
		 u8 **prev_merkles,
		 struct protocol_block_tailer **tailer)
{
	struct protocol_block_header *hdr = (void *)&buffer->block;
	size_t size = le32_to_cpu(buffer->len), len, merkle_len;

	assert(buffer->type == cpu_to_le32(PROTOCOL_REQ_NEW_BLOCK));

	if (size < sizeof(*hdr))
		return NULL;

	if (!version_ok(hdr->version))
		return NULL;

	if (add_overflows(le32_to_cpu(hdr->num_transactions),
			  (1<<PETTYCOIN_BATCH_ORDER)-1))
		return NULL;

	len = sizeof(*hdr);

	/* Merkles come after header. */
	*merkles = (struct protocol_double_sha *)(hdr + 1);

	merkle_len = num_merkles(le32_to_cpu(hdr->num_transactions));

	/* This can't actually happen, due to shift, but be thorough. */
	if (mul_overflows(merkle_len, sizeof(struct protocol_double_sha)))
		return NULL;
	merkle_len *= sizeof(struct protocol_double_sha);

	if (add_overflows(len, merkle_len))
		return NULL;

	len += merkle_len;

	/* Next comes prev_merkles. */
	*prev_merkles = (u8 *)hdr + len;
	if (add_overflows(len, le32_to_cpu(hdr->num_prev_merkles)))
		return NULL;
	len += le32_to_cpu(hdr->num_prev_merkles);

	/* Finally comes tailer. */
	*tailer = (struct protocol_block_tailer *)
		(*prev_merkles + le32_to_cpu(hdr->num_prev_merkles));

	if (add_overflows(len, sizeof(**tailer)))
		return NULL;

	len += sizeof(**tailer);

	/* Size must be exactly right. */
	if (size != len)
		return NULL;

	return hdr;
}

struct protocol_req_new_block *
marshall_block(const tal_t *ctx,
	       const struct protocol_block_header *hdr,
	       const struct protocol_double_sha *merkles,
	       const u8 *prev_merkles,
	       const struct protocol_block_tailer *tailer)
{
	struct protocol_req_new_block *ret;
	size_t len, merkle_len, prev_merkle_len;

	merkle_len = sizeof(*merkles)
		* num_merkles(le32_to_cpu(hdr->num_transactions));
	prev_merkle_len = sizeof(*prev_merkles)
		* le32_to_cpu(hdr->num_prev_merkles);

	len = sizeof(*hdr) + merkle_len + prev_merkle_len + sizeof(*tailer);
	ret = talv(ctx, struct protocol_req_new_block, block[len]);

	ret->len = cpu_to_le32(len);
	ret->type = cpu_to_le32(PROTOCOL_REQ_NEW_BLOCK);

	memcpy(ret->block, hdr, sizeof(*hdr));
	memcpy(ret->block + sizeof(*hdr), merkles, merkle_len);
	memcpy(ret->block + sizeof(*hdr) + merkle_len,
	       prev_merkles, prev_merkle_len);
	memcpy(ret->block + sizeof(*hdr) + merkle_len + prev_merkle_len,
	       tailer, sizeof(*tailer));
	return ret;
}

/* Make sure transaction is all there, convert. */
union protocol_transaction *unmarshall_transaction(void *buffer, size_t size)
{
	union protocol_transaction *t = buffer;
	size_t i;

	if (size < sizeof(t->hdr))
		return NULL;

	if (!version_ok(t->hdr.version))
		return NULL;

	switch (t->hdr.type) {
	case TRANSACTION_NORMAL:
		if (size < sizeof(t->normal))
			return NULL;
		if (mul_overflows(sizeof(t->normal.input[0]),
				  le16_to_cpu(t->normal.num_inputs)))
			return NULL;
		i = sizeof(t->normal.input[0])
			* le16_to_cpu(t->normal.num_inputs);

		if (add_overflows(sizeof(t->normal), i))
			return NULL;
		if (size != sizeof(t->normal) + i)
			return NULL;
		break;
	case TRANSACTION_FROM_GATEWAY:
		if (size < sizeof(t->gateway))
			return NULL;
		
		if (mul_overflows(sizeof(t->gateway.output[0]),
				  le16_to_cpu(t->gateway.num_outputs)))
			return NULL;
		i = sizeof(t->gateway.output[0])
			* le16_to_cpu(t->gateway.num_outputs);

		if (add_overflows(sizeof(t->gateway), i))
			return NULL;

		if (size != sizeof(t->gateway) + i)
			return NULL;
		break;
	default:
		/* Unknown type. */
		return NULL;
	}

	return t;
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
			       input, le16_to_cpu(t->normal.num_inputs));
	case TRANSACTION_FROM_GATEWAY:
		return varsize(struct protocol_transaction_gateway,
			       output, le16_to_cpu(t->gateway.num_outputs));
	}
	abort();
}
