#ifndef PETTYCOIN_PROOF_H
#define PETTYCOIN_PROOF_H
#include <ccan/short_types/short_types.h>
#include <stdbool.h>

struct protocol_proof;
struct block;
union protocol_transaction;

void create_proof(struct protocol_proof *proof,
		  const struct block *block,
		  u32 tnum);

bool check_proof(const struct protocol_proof *proof,
		 const struct block *block,
		 const union protocol_transaction *t,
		 u32 tnum);

#endif /* PETTYCOIN_PROOF_H */
