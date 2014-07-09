#ifndef PETTYCOIN_GENERATE_H
#define PETTYCOIN_GENERATE_H
#include "config.h"
#include "protocol_net.h"

/* Write this to generate's stdin to add a new transaction. */
struct gen_update {
	u16 shard;
	u8 txoff;
	u8 unused;
	u32 features;
	struct protocol_net_txrefhash hashes;
};

#endif /* PETTYCOIN_GENERATE_H */
