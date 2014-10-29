#include <ccan/strmap/strmap.h>
#include <ccan/tal/str/str.h>

struct strmap_block {
	STRMAP_MEMBERS(struct block *);
};
static struct strmap_block blockmap;
static bool blockmap_initialized = false;

static struct block *add_next_block(struct state *state,
				    struct block *prev, const char *name,
				    unsigned int tx_count,
				    u8 shard_order,
				    const struct protocol_address *addr)
{
	struct block *b;
	struct block_info bi;
	struct protocol_block_header *hdr;
	struct protocol_block_tailer *tailer;
	u8 *num_txs;
	struct protocol_block_id dummy = { { { 0 } } };

	hdr = tal(state, struct protocol_block_header);
	hdr->shard_order = shard_order;
	hdr->height = cpu_to_le32(block_height(&prev->bi) + 1);
	hdr->prevs[0] = prev->sha;
	hdr->fees_to = *addr;

	tailer = tal(state, struct protocol_block_tailer);
	tailer->difficulty = cpu_to_le32(block_difficulty(&prev->bi));

	num_txs = tal_arrz(state, u8, 1 << hdr->shard_order);
	num_txs[0] = tx_count;

	memcpy(&dummy, name,
	       strlen(name) < sizeof(dummy) ? strlen(name) : sizeof(dummy));

	bi.hdr = hdr;
	bi.tailer = tailer;
	bi.num_txs = num_txs;
	b = block_add(state, prev, &dummy, &bi);

	if (!blockmap_initialized) {
		strmap_init(&blockmap);
		blockmap_initialized = true;
	}

	strmap_add(&blockmap, name, b);
	return b;
}

/* Inline in case a test doesn't use it... */
static inline void create_chain(struct state *state, struct block *base,
				const char *prefix,
				const struct protocol_address *addr,
				u8 shard_order,
				unsigned int num, bool known)
{
	unsigned int i;

	for (i = 0; i < num; i++) {
		char *name = tal_fmt(state, "%s-%u", prefix, i);
		base = add_next_block(state, base, name, known ? 0 : 1,
				      shard_order, addr);
		known = true;
	}
}

