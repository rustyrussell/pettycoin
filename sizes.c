#include "protocol.h"
#include "block.h"
#include <ccan/err/err.h>
#include <stdio.h>
#include <stdlib.h>

#define PROTOCOL_NET_SHARD_BITS 10
#define AVERAGE_INPUTS 2.1

int main(int argc, char *argv[])
{
	unsigned long long tps, tsize, trans_per_block, merkles_per_block,
		blocksize;

	if (argc != 2)
		errx(1, "Usage: sizes <tps>");

	tps = atoi(argv[1]);
	tsize = sizeof(struct protocol_transaction_normal)
		+ sizeof(struct protocol_input) * AVERAGE_INPUTS;
	printf("# Assuming %f average inputs => tsize %llu bytes\n",
	       AVERAGE_INPUTS, tsize);
	trans_per_block = tps * 600;
	printf("Transactions per block: %llu\n", trans_per_block);
	merkles_per_block = num_batches(trans_per_block);
	blocksize = sizeof(struct protocol_block_header)
		+ merkles_per_block * sizeof(struct protocol_double_sha)
		+ merkles_per_block * PETTYCOIN_PREV_BLOCK_MERKLES
		+ sizeof(struct protocol_block_tailer);
	printf("Block size: %llu\n", blocksize);

	/* Miners need every transaction + every block. */
	printf("Miners: %llu + %llu = %llu bytes per second\n",
	       tps * tsize, blocksize / 600,
	       tps * tsize + blocksize / 600);

	/* Minimal node needs two shards + every block. */
	printf("Minimal nodes: %llu + %llu = %llu bytes per second\n",
	       ((tps * tsize) >> PROTOCOL_NET_SHARD_BITS) * 2, blocksize / 600,
	       ((tps * tsize) >> PROTOCOL_NET_SHARD_BITS) * 2 + blocksize / 600);

	return 0;
}
