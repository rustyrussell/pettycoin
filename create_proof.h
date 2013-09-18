#ifndef PETTYCOIN_CREATE_PROOF_H
#define PETTYCOIN_CREATE_PROOF_H
struct state;
union protocol_transaction;

struct protocol_proof *create_proof(struct state *state,
				    const union protocol_transaction *trans,
				    union protocol_transaction ***transarr);
#endif /* PETTYCOIN_CREATE_PROOF_H */
