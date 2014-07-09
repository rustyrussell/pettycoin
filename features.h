#ifndef PETTYCOIN_FEATURES_H
#define PETTYCOIN_FEATURES_H
#include "config.h"
#include <ccan/short_types/short_types.h>
#include <stdbool.h>

static inline u8 current_features(void)
{
	return 0;
}

static inline bool features_ok(u8 features)
{
	return features == current_features();
}

struct block;
u8 pending_features(const struct block *block);

#endif /* PETTYCOIN_FEATURES_H */
