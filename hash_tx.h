#ifndef PETTYCOIN_HASH_TX_H
#define PETTYCOIN_HASH_TX_H
#include "config.h"
#include <stddef.h>

union protocol_tx;
struct protocol_double_sha;
struct protocol_tx_id;
struct protocol_input_ref;
struct protocol_txrefhash;

/* Get hash, by which we refer to transaction. */
void hash_tx(const union protocol_tx *tx, struct protocol_tx_id *txid);

/* Get refhash, which we merkle with txhash inside a block. */
void hash_refs(const struct protocol_input_ref *refs,
	       size_t num_refs,
	       struct protocol_double_sha *sha);

/* Combo deal. */
void hash_tx_and_refs(const union protocol_tx *tx,
		      const struct protocol_input_ref *refs,
		      struct protocol_txrefhash *txrefhash);

#endif /* PETTYCOIN_HASH_TX_H */
