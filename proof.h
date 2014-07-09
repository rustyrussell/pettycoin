#ifndef PETTYCOIN_PROOF_H
#define PETTYCOIN_PROOF_H
#include <ccan/short_types/short_types.h>
#include <stdbool.h>

struct protocol_proof;
struct block;
union protocol_tx;
struct protocol_input_ref;
struct block_shard;
struct protocol_net_txrefhash;

void create_proof(struct protocol_proof *proof,
		  const struct block_shard *shard, u8 txoff);

bool check_proof(const struct protocol_proof *proof,
		 const struct block *b,
		 u16 shardnum, u8 txoff,
		 const union protocol_tx *tx,
		 const struct protocol_input_ref *refs);

bool check_proof_byhash(const struct protocol_proof *proof,
			const struct block *b,
			u16 shardnum, u8 txoff,
			const struct protocol_net_txrefhash *txrefhash);

#endif /* PETTYCOIN_PROOF_H */
