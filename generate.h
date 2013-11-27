#ifndef PETTYCOIN_GENERATE_H
#define PETTYCOIN_GENERATE_H
#include <ccan/short_types/short_types.h>

/* Write this to generate's stdin to add a new transaction. */
struct update {
	u32 trans_idx;
	u32 features;
	const void *cookie;
	struct protocol_double_sha hash;
};

#endif /* PETTYCOIN_GENERATE_H */
