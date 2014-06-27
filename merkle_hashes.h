#ifndef PETTYCOIN_MERKLE_HASHES_H
#define PETTYCOIN_MERKLE_HASHES_H
#include <stddef.h>

struct protocol_double_sha;

/* For generator, which already has them as hashes. */
void merkle_hashes(const struct protocol_double_sha **hashes,
		   size_t off, size_t num_hashes,
		   struct protocol_double_sha *merkle);

#endif /* PETTYCOIN_MERKLE_HASHES_H */


