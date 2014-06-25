#include "../marshall.c"
#include "../minimal_log.c"
#include <assert.h>

static void test_marshall(const struct protocol_block_header *hdr,
			  const u8 *shard_nums,
			  const struct protocol_double_sha *merkles,
			  const u8 *prev_merkles,
			  const struct protocol_block_tailer *tailer)
{
	struct protocol_pkt_block *pkt;
	const struct protocol_block_header *hdr2;
	const u8 *shard_nums2;
	const struct protocol_double_sha *merkles2;
	const u8 *prev_merkles2;
	const struct protocol_block_tailer *tailer2;

	char *ctx = tal(NULL, char);

	pkt = marshall_block(ctx, hdr, shard_nums, merkles, prev_merkles,
			     tailer);
	assert(tal_parent(pkt) == ctx);
	assert(tal_count(pkt) == le32_to_cpu(pkt->len));

	assert(unmarshall_block(NULL, pkt, &hdr2,
				&shard_nums2, &merkles2, &prev_merkles2,
				&tailer2) == PROTOCOL_ECODE_NONE);
	assert(memcmp(hdr2, hdr, sizeof(*hdr)) == 0);
	assert(memcmp(shard_nums2, shard_nums, 
		      sizeof(*shard_nums) << hdr->shard_order) == 0);
	assert(memcmp(merkles2, merkles,
		      sizeof(*merkles) << hdr->shard_order) == 0);
	assert(memcmp(prev_merkles2, prev_merkles,
		      le32_to_cpu(hdr->num_prev_merkles)) == 0);
	assert(memcmp(tailer2, tailer, sizeof(*tailer)) == 0);

	tal_free(pkt);
}

int main(int argc, char *argv[])
{
	struct protocol_block_header hdr;
	u8 shard_nums[2 << PROTOCOL_INITIAL_SHARD_ORDER];
	struct protocol_double_sha merkles[2 << PROTOCOL_INITIAL_SHARD_ORDER];
	u8 prev_merkles[16];
	struct protocol_block_tailer tailer;

	/* Basic test. */
	hdr.version = 1;
	hdr.features_vote = 0;
	hdr.shard_order = PROTOCOL_INITIAL_SHARD_ORDER;
	memset(hdr.nonce2, 7, sizeof(hdr.nonce2));
	memset(&hdr.prev_block, 8, sizeof(hdr.prev_block));
	hdr.num_prev_merkles = cpu_to_le32(0);
	hdr.depth = cpu_to_le32(0);
	memset(&hdr.fees_to, 9, sizeof(hdr.fees_to));

	memset(shard_nums, 0, sizeof(shard_nums[0]) << hdr.shard_order);

	memset(merkles, 10, sizeof(merkles[0]) << hdr.shard_order);

	tailer.timestamp = cpu_to_le32(12345678);
	tailer.difficulty = cpu_to_le32(0x1effffff);
	tailer.nonce1 = cpu_to_le32(11);

	test_marshall(&hdr, shard_nums, merkles, prev_merkles, &tailer);

	/* Test feature vote works. */
	hdr.features_vote = 0x10;
	test_marshall(&hdr, shard_nums, merkles, prev_merkles, &tailer);

	/* Test prev_merkles works. */
	hdr.num_prev_merkles = cpu_to_le32(4);
	memset(prev_merkles, 12, 4);
	test_marshall(&hdr, shard_nums, merkles, prev_merkles, &tailer);

	/* Test increasing shard order. */
	hdr.shard_order = PROTOCOL_INITIAL_SHARD_ORDER + 1;
	memset(shard_nums, 0, sizeof(shard_nums[0]) << hdr.shard_order);
	memset(merkles, 13, sizeof(merkles[0]) << hdr.shard_order);
	test_marshall(&hdr, shard_nums, merkles, prev_merkles, &tailer);

	return 0;
}
