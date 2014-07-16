#include "block.h"
#include "blockfile.h"
#include "check_block.h"
#include "marshal.h"
#include "packet_io.h"
#include "proof.h"
#include "protocol_net.h"
#include "recv_tx.h"
#include "shard.h"
#include "state.h"
#include "tal_packet.h"
#include <ccan/err/err.h>
#include <ccan/io/io.h>
#include <ccan/read_write_all/read_write_all.h>
#include <fcntl.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static bool load_block(struct state *state, struct protocol_net_hdr *pkt)
{
	struct block *prev, *block;
	enum protocol_ecode e;
	const u8 *shard_nums;
	const struct protocol_double_sha *merkles;
	const u8 *prev_txhashes;
	const struct protocol_block_tailer *tailer;
	const struct protocol_block_header *hdr;
	struct protocol_double_sha sha;

	e = unmarshal_block(state->log, (void *)pkt,
			    &hdr, &shard_nums, &merkles, &prev_txhashes,
			    &tailer);
	if (e != PROTOCOL_ECODE_NONE)
		return false;

	e = check_block_header(state, hdr, shard_nums, merkles, prev_txhashes,
			       tailer, &prev, &sha);
	if (e != PROTOCOL_ECODE_NONE)
		return false;

	block = block_add(state, prev, &sha,
			  hdr, shard_nums, merkles, prev_txhashes, tailer);

	/* Now new block owns the packet. */
	tal_steal(block, pkt);
	return true;
}

static bool load_tx_in_block(struct state *state,
			     const struct protocol_pkt_tx_in_block *pkt)
{
	enum protocol_ecode e;

	e = recv_tx_from_blockfile(state, pkt);
	tal_free(pkt);

	return e == PROTOCOL_ECODE_NONE;
}

void load_blocks(struct state *state)
{
	off_t off = 0;
	struct stat st;
	int fd;

	fd = open("blockfile", O_RDWR|O_CREAT, 0600);
	if (fd < 0)
		err(1, "Opening blockfile");

	/* Prevent us saving blocks as we're reading them. */
	state->blockfd = -1;

	for (;;) {
		struct protocol_net_hdr *pkt;
		struct io_plan plan;
		int ret;

		plan = io_read_packet_(&pkt, (void *)1, NULL);
		while ((ret = plan.io(fd, &plan)) != 1) {
			if (ret == -1) {
				/* Did we do a partial read? */
				if (lseek(fd, 0, SEEK_CUR) != off) {
					log_unusual(state->log,
						    "blockfile partial read");
					goto truncate;
				}
				goto out;
			}
		}

		switch (le32_to_cpu(pkt->type)) {
		case PROTOCOL_PKT_BLOCK:
			if (!load_block(state, pkt)) {
				log_unusual(state->log,
					    "blockfile partial block");
				goto truncate;
			}
			break;
		case PROTOCOL_PKT_TX_IN_BLOCK:
			if (!load_tx_in_block(state, (const void *)pkt)) {
				log_unusual(state->log,
					    "blockfile partial transaction");
				goto truncate;
			}
			break;
		default:
			log_unusual(state->log, "blockfile unknown type %u",
				    le32_to_cpu(pkt->type));
			goto truncate;
		}
		off += le32_to_cpu(pkt->len);
	}

truncate:
	fstat(fd, &st);
	log_unusual(state->log, "Truncating blockfile from %llu to %llu",
		    (long long)st.st_size, (long long)off);
	ftruncate(fd, off);
	lseek(fd, SEEK_SET, off);

out:
	/* Now we can save more. */
	state->blockfd = fd;
}

void save_block(struct state *state, struct block *new)
{
	struct protocol_pkt_block *blk;
	size_t len;

	/* Don't save while we're still loading. */
	if (state->blockfd == -1)
		return;

	blk = marshal_block(state,
			    new->hdr, new->shard_nums, new->merkles,
			    new->prev_txhashes, new->tailer);
	len = le32_to_cpu(blk->len);

	if (!write_all(state->blockfd, blk, len))
		err(1, "writing block to blockfile");

	tal_free(blk);
}

void save_tx(struct state *state, struct block *block, u16 shard, u8 txoff)
{
	struct protocol_proof proof;
	struct protocol_pkt_tx_in_block *pkt;

	/* Don't save while we're still loading. */
	if (state->blockfd == -1)
		return;

	pkt = tal_packet(state, struct protocol_pkt_tx_in_block,
			 PROTOCOL_PKT_TX_IN_BLOCK);

	pkt->err = cpu_to_le32(PROTOCOL_ECODE_NONE);
	create_proof(&proof, block, shard, txoff);
	tal_packet_append_proven_tx(&pkt, &proof,
				    block_get_tx(block, shard, txoff),
				    block_get_refs(block, shard, txoff));

	if (!write_all(state->blockfd, pkt, le32_to_cpu(pkt->len)))
		err(1, "writing tx to blockfile");

	tal_free(pkt);	
}
