#include "merkle_hashes.h"
#include "merkle_recurse.h"
#include "protocol.h"

static void merkle_hash(size_t n, void *data,
			struct protocol_double_sha *merkle)
{
	const struct protocol_double_sha **hashes = data;

	*merkle = *hashes[n];
}

void merkle_hashes(const struct protocol_double_sha **hashes,
		   size_t off, size_t num_hashes,
		   struct protocol_double_sha *merkle)
{
	merkle_recurse(off, num_hashes, 256, merkle_hash, hashes, merkle);
}
