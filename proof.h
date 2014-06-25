#ifndef PETTYCOIN_PROOF_H
#define PETTYCOIN_PROOF_H
#include <ccan/short_types/short_types.h>
#include <stdbool.h>

struct protocol_proof;
struct block;
union protocol_transaction;

void create_proof(struct protocol_proof *proof,
		  const struct block *block, u16 shardnum, u8 txoff);

bool check_proof(const struct protocol_proof *proof,
		 const struct block *block,
		 const union protocol_transaction *t,
		 u16 shardnum, u8 txoff);

#endif /* PETTYCOIN_PROOF_H */
