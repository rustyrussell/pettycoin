#include "block.h"
#include "features.h"
#include <ccan/array_size/array_size.h>

u8 pending_features(const struct block *block)
{
	u32 feature_counts[8] = { 0 };
	const struct block *b;
	unsigned int i, j;
	u8 result = 0;

	/* We only update pending features every FEATURE_VOTE_BLOCKS blocks */
	if (le32_to_cpu(block->hdr->depth) % PROTOCOL_FEATURE_VOTE_BLOCKS != 0)
		return block->prev->pending_features;

	for (b = block, i = 0;
	     i < PROTOCOL_FEATURE_VOTE_BLOCKS;
	     i++, b = b->prev) {
		for (j = 0; j < ARRAY_SIZE(feature_counts); j++) {
			if (b->hdr->features_vote & (1 << j))
				feature_counts[j]++;
		}
	}

	/* If 75% of blocks accept feature, we have supermajority. */
	for (j = 0; j < ARRAY_SIZE(feature_counts); j++) {
		if (feature_counts[j] * 4 / PROTOCOL_FEATURE_VOTE_BLOCKS >= 3)
			result |= 1 << j;
	}
	return result;
}
