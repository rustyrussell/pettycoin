#ifndef PETTYCOIN_COMPLAIN_H
#define PETTYCOIN_COMPLAIN_H
#include "config.h"
#include "protocol_ecode.h"
#include <ccan/short_types/short_types.h>
#include <stdlib.h>

struct state;
struct block;
union protocol_tx;
struct protocol_input_ref;
struct protocol_proof;
struct peer;

/* This can never happen, since there's no way to send an invalid tx. */
void complain_bad_tx(struct state *state,
		     struct block *block,
		     enum protocol_ecode err,
		     const struct protocol_proof *proof,
		     const union protocol_tx *tx,
		     const struct protocol_input_ref *refs);

/* tx/refs belongs in block at shardnum/tx, but input bad_input is bad. */
void complain_bad_input(struct state *state,
			struct block *block,
			const struct protocol_proof *proof,
			const union protocol_tx *tx,
			const struct protocol_input_ref *refs,
			unsigned int bad_input,
			const union protocol_tx *intx);

/* tx/refs belongs in block at shardnum/tx, but inputs don't add up. */
void complain_bad_amount(struct state *state,
			 struct block *block,
			 const struct protocol_proof *proof,
			 const union protocol_tx *tx,
			 const struct protocol_input_ref *refs,
			 const union protocol_tx *intx[]);

/* tx/refs belongs in block at shardnum/tx, but input ref points to a
 * different tx to the tx referred to by tx->input. */
void complain_bad_input_ref(struct state *state,
			    struct block *block,
			    const struct protocol_proof *proof,
			    const union protocol_tx *tx,
			    const struct protocol_input_ref *refs,
			    unsigned int bad_refnum,
			    const struct block *block_referred_to);

/* We found two transactions which spend the same inputs, in blocks
 * which are in the same chain (even the same block!).
 * block1 preceeds block2, so block2 is bad. */
void complain_doublespend(struct state *state,
			  struct block *block1,
			  u32 input1,
			  const struct protocol_proof *proof1,
			  const union protocol_tx *tx1,
			  const struct protocol_input_ref *refs1,
			  struct block *block2,
			  u32 input2,
			  const struct protocol_proof *proof2,
			  const union protocol_tx *tx2,
			  const struct protocol_input_ref *refs2);

/* tx/refs belongs in block at shardnum/tx, but it's out of order when
 * compared with the already-known tx conflict_txoff. */
void complain_misorder(struct state *state,
		       struct block *block,
		       const struct protocol_proof *proof,
		       const union protocol_tx *tx,
		       const struct protocol_input_ref *refs,
		       unsigned int conflict_txoff);

void publish_complaint(struct state *state,
		       struct block *block,
		       const void *complaint,
		       struct peer *origin);
#endif /* PETTYCOIN_COMPLAIN_H */
