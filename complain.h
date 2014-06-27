#ifndef PETTYCOIN_COMPLAIN_H
#define PETTYCOIN_COMPLAIN_H
#include "protocol_ecode.h"

struct state;
struct block;
union protocol_tx;

void complain_bad_tx(struct state *state,
		     struct block *block,
		     enum protocol_ecode err,
		     unsigned int bad_shardnum,
		     unsigned int bad_txoff,
		     unsigned int bad_input,
		     union protocol_tx *bad_intx);

void complain_misorder(struct state *state,
		       struct block *block,
		       unsigned int bad_shardnum,
		       unsigned int bad_txoff1,
		       unsigned int bad_txoff2);

#endif /* PETTYCOIN_COMPLAIN_H */
