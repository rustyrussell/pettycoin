#ifndef PETTYCOIN_MERKLE_RECURSE_H
#define PETTYCOIN_MERKLE_RECURSE_H
#include "config.h"
#include <stddef.h>

struct protocol_double_sha;

void merkle_recurse(size_t off, size_t max_off, size_t num,
		    void (*fn)(size_t n, void *data,
			       struct protocol_double_sha *merkle),
		    void *data,
		    struct protocol_double_sha *merkle);

/* Helper to merkle two hashes together: SHA256(SHA256([a][b])) */
void merkle_two_hashes(const struct protocol_double_sha *a,
		       const struct protocol_double_sha *b,
		       struct protocol_double_sha *merkle);

#endif /* PETTYCOIN_MERKLE_RECURSE_H */


