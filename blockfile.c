#include "protocol_net.h"
#include "state.h"
#include "marshall.h"
#include "check_block.h"
#include "block.h"
#include "blockfile.h"
#include "packet.h"
#include "packet_io.h"
#include "shard.h"
#include <ccan/err/err.h>
#include <ccan/io/io.h>
#include <ccan/read_write_all/read_write_all.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

static bool load_block(struct state *state, struct protocol_net_hdr *pkt)
{
	struct block *new;
	enum protocol_ecode e;
	const u8 *shard_nums;
	const struct protocol_double_sha *merkles;
	const u8 *prev_merkles;
	const struct protocol_block_tailer *tailer;
	const struct protocol_block_header *hdr;

	e = unmarshall_block(state->log, (void *)pkt,
			     &hdr, &shard_nums, &merkles, &prev_merkles,
			     &tailer);
	if (e != PROTOCOL_ECODE_NONE)
		return false;

	e = check_block_header(state, hdr, shard_nums, merkles, prev_merkles,
			       tailer, &new, NULL);
	if (e != PROTOCOL_ECODE_NONE)
		return false;

	block_add(state, new);
	return true;
}

/* FIXME: Use struct protocol_pkt_tx_in_block, or at least sha to
 * detect corruption. */
static bool load_transaction(struct state *state, struct protocol_net_hdr *pkt)
{
	return false;
}

void load_blocks(struct state *state)
{
	off_t off = 0;
	struct stat st;

	state->blockfd = open("blockfile", O_RDWR|O_CREAT, 0600);
	if (state->blockfd < 0)
		err(1, "Opening blockfile");

	for (;;) {
		struct protocol_net_hdr *pkt;
		struct io_plan plan;
		int ret;

		plan = io_read_packet_(&pkt, (void *)1, NULL);
		while ((ret = plan.io(state->blockfd, &plan)) != 1) {
			if (ret == -1) {
				/* Did we do a partial read? */
				if (lseek(state->blockfd, 0, SEEK_CUR) != off) {
					log_unusual(state->log,
						    "blockfile partial read");
					goto truncate;
				}
				return;
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
		case PROTOCOL_PKT_TX:
			if (!load_transaction(state, pkt)) {
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
	fstat(state->blockfd, &st);
	log_unusual(state->log, "Truncating blockfile from %llu to %llu",
		    (long long)st.st_size, (long long)off);
	ftruncate(state->blockfd, off);
	lseek(state->blockfd, SEEK_SET, off);
}

void save_block(struct state *state, struct block *new)
{
	struct protocol_pkt_block *blk;
	size_t len;

	blk = marshall_block(state,
			     new->hdr, new->shard_nums, new->merkles,
			     new->prev_merkles, new->tailer);
	len = le32_to_cpu(blk->len);
	if (!write_all(state->blockfd, blk, len))
		err(1, "writing block to blockfile");

	tal_free(blk);
}

void save_shard(struct state *state, struct block *block, u16 shardnum)
{
	/* FIXME! */
}
