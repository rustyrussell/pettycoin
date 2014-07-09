#ifndef PETTYCOIN_PROOF_H
#define PETTYCOIN_PROOF_H
#include "config.h"
#include <ccan/short_types/short_types.h>
#include <stdbool.h>

struct protocol_proof;
struct block;
union protocol_tx;
struct protocol_input_ref;
struct block_shard;
struct protocol_txrefhash;

void create_proof(struct protocol_proof *proof,
		  const struct block *block, u16 shard, u8 txoff);

bool check_proof(const struct protocol_proof *proof,
		 const struct block *b,
		 const union protocol_tx *tx,
		 const struct protocol_input_ref *refs);

bool check_proof_byhash(const struct protocol_proof *proof,
			const struct block *b,
			const struct protocol_txrefhash *txrefhash);

#endif /* PETTYCOIN_PROOF_H */
