#include "merkle_hashes.h"
#include "merkle_recurse.h"
#include "protocol.h"
#include "protocol_net.h"

static void merkle_hash(size_t n, void *data,
			struct protocol_double_sha *merkle)
{
	const struct protocol_txrefhash *hashes = data;

	merkle_two_hashes(&hashes[n].txhash.sha, &hashes[n].refhash, merkle);
}

void merkle_hashes(const struct protocol_txrefhash *hashes,
		   size_t off, size_t num_hashes,
		   struct protocol_double_sha *merkle)
{
	merkle_recurse(off, num_hashes, 256, merkle_hash, (void *)hashes,
		       merkle);
}
