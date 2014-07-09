#ifndef PETTYCOIN_MERKLE_HASHES_H
#define PETTYCOIN_MERKLE_HASHES_H
#include "config.h"
#include <stddef.h>

struct protocol_double_sha;
struct protocol_txrefhash;

/* For when we already has them as flat array of hashes. */
void merkle_hashes(const struct protocol_txrefhash *hashes,
		   size_t off, size_t num_hashes,
		   struct protocol_double_sha *merkle);

#endif /* PETTYCOIN_MERKLE_HASHES_H */


