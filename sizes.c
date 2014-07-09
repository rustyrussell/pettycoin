#include "protocol.h"
#include "block.h"
#include <ccan/err/err.h>
#include <stdio.h>
#include <stdlib.h>

#define AVERAGE_INPUTS 2.1

static char *format_si(unsigned long long x)
{
	static char buf[100];
	const char *suffix[] = { "", "Kilo", "Mega", "Giga", "Tera", NULL };
	unsigned int i = 0;

	while (x > 100 * 1024) {
		if (!suffix[i+1])
			break;
		i++;
		x /= 1024;
	}

	sprintf(buf, "%llu %sbytes", x, suffix[i]);
	return buf;
}

int main(int argc, char *argv[])
{
	unsigned long long tps, tsize, trans_per_block, merkles_per_block,
		blocksize, shard_order, txbytes_per_sec, blockbytes_per_sec;

	if (argc != 2)
		errx(1, "Usage: sizes <tps>");

	tps = atoi(argv[1]);
	tsize = sizeof(struct protocol_tx_normal)
		+ sizeof(struct protocol_input) * AVERAGE_INPUTS;
	printf("# Assuming %f average inputs => tsize %llu bytes\n",
	       AVERAGE_INPUTS, tsize);
	trans_per_block = tps * PROTOCOL_BLOCK_TARGET_TIME;
	printf("Transactions per block: %llu\n", trans_per_block);
	/* Increase shard order until shards are half full. */
	for (shard_order = PROTOCOL_INITIAL_SHARD_ORDER;
	     (128 << shard_order) < trans_per_block;
	     shard_order++);

	printf("Shards: (2^%llu) %llu\n", shard_order, 1ULL << shard_order);
	if (shard_order > 16) {
		printf("*** Truncating shards to 2^16 (need u32 shardnum!)\n");
		shard_order = 16;
	}

	merkles_per_block = (1 << shard_order);
	blocksize = sizeof(struct protocol_block_header)
		+ merkles_per_block * sizeof(struct protocol_double_sha)
		+ merkles_per_block * PROTOCOL_PREV_BLOCK_TXHASHES
		+ sizeof(struct protocol_block_tailer);
	printf("Block size: %llu\n", blocksize);

	txbytes_per_sec = tps * tsize;
	blockbytes_per_sec = blocksize / PROTOCOL_BLOCK_TARGET_TIME;

	printf("%-15s%15s%15s%15s %s\n",
	       "", "Transactions", "Blocks", "Total", "Units");

	/* Miners need every transaction + every block. */
	printf("%-15s%15llu%15llu%15llu %s\n",
	       "Miners pipe",
	       txbytes_per_sec, blockbytes_per_sec,
	       txbytes_per_sec + blockbytes_per_sec,
	       "bytes per second");
	printf("%-15s%15llu%15llu%25s\n",
	       "Miners storage",
	       txbytes_per_sec * PROTOCOL_TX_HORIZON_SECS,
	       blockbytes_per_sec * PROTOCOL_TX_HORIZON_SECS,
	       format_si(txbytes_per_sec * PROTOCOL_TX_HORIZON_SECS
			 + blockbytes_per_sec * PROTOCOL_TX_HORIZON_SECS));

	/* Minimal node needs two shards + every block. */
	txbytes_per_sec >>= shard_order - 1;
	printf("%-15s%15llu%15llu%15llu %s\n",
	       "Minimal pipe",
	       txbytes_per_sec, blockbytes_per_sec,
	       txbytes_per_sec + blockbytes_per_sec,
	       "bytes per second");
	printf("%-15s%15llu%15llu%25s\n",
	       "Minimal storage",
	       txbytes_per_sec * PROTOCOL_TX_HORIZON_SECS,
	       blockbytes_per_sec * PROTOCOL_TX_HORIZON_SECS,
	       format_si(txbytes_per_sec * PROTOCOL_TX_HORIZON_SECS
			 + blockbytes_per_sec * PROTOCOL_TX_HORIZON_SECS));
	return 0;
}
