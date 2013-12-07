#include "protocol_net.h"
#include "state.h"
#include "marshall.h"
#include "check_block.h"
#include "block.h"
#include "blockfile.h"
#include "packet.h"
#include <ccan/err/err.h>
#include <ccan/io/io.h>
#include <ccan/read_write_all/read_write_all.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

struct block_transaction {
	le32 len;
	le32 type; /* == PROTOCOL_REQ_NEW_GATEWAY_TRANSACTION */
	struct protocol_double_sha block;
	le32 num;
	/* Followed by union protocol_transaction trans */
};

static bool load_block(struct state *state, struct protocol_net_hdr *pkt)
{
	struct block *new;
	enum protocol_error e;
	const struct protocol_double_sha *merkles;
	const u8 *prev_merkles;
	const struct protocol_block_tailer *tailer;
	struct protocol_block_header *hdr = (void *)(pkt + 1);

	e = unmarshall_block(state->log, le32_to_cpu(pkt->len) - sizeof(*pkt),
			     hdr, &merkles, &prev_merkles, &tailer);
	if (e != PROTOCOL_ERROR_NONE)
		return false;

	e = check_block_header(state, hdr, merkles, prev_merkles,
			       tailer, &new);
	if (e != PROTOCOL_ERROR_NONE)
		return false;

	block_add(state, new);
	return true;
}

static bool load_transaction(struct state *state, struct protocol_net_hdr *pkt)
{
	struct block_transaction *hdr = (void *)pkt;
	struct transaction_batch *batch;
	union protocol_transaction *t;
	struct block *block;
	u32 num;

	if (le32_to_cpu(hdr->len) < sizeof(*hdr))
		return false;

	block = block_find_any(state, &hdr->block);
	if (!block)
		return false;

	num = le32_to_cpu(hdr->num);
	if (num >= le32_to_cpu(block->hdr->num_transactions))
		return false;

	t = (void *)(hdr + 1);
	if (unmarshall_transaction(t, le32_to_cpu(hdr->len) - sizeof(*hdr))
	    != PROTOCOL_ERROR_NONE)
		return false;

	batch = block->batch[batch_index(num)];
	batch->t[num % (1 << PETTYCOIN_BATCH_ORDER)] = t;
	return true;
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
		case PROTOCOL_REQ_NEW_BLOCK:
			if (!load_block(state, pkt)) {
				log_unusual(state->log,
					    "blockfile partial block");
				goto truncate;
			}
			break;
		case PROTOCOL_REQ_NEW_GATEWAY_TRANSACTION:
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
	struct protocol_req_new_block *blk;
	size_t len;

	blk = marshall_block(state,
			     new->hdr, new->merkles, new->prev_merkles,
			     new->tailer);
	len = le32_to_cpu(blk->len);
	if (!write_all(state->blockfd, blk, len))
		err(1, "writing block to blockfile");

	tal_free(blk);
}

void save_transaction(struct state *state, struct block *b, u32 i)
{
	union protocol_transaction *t = block_get_trans(b, i);
	size_t len;
	struct block_transaction hdr;

	assert(t);

	len = marshall_transaction_len(t);
	hdr.len = cpu_to_le32(sizeof(hdr) + len);
	if (t->hdr.type == TRANSACTION_FROM_GATEWAY)
		hdr.type = PROTOCOL_REQ_NEW_GATEWAY_TRANSACTION;
	else
		abort();
	hdr.block = b->sha;
	hdr.num = cpu_to_le32(i);

	if (!write_all(state->blockfd, &hdr, sizeof(hdr))
	    || !write_all(state->blockfd, t, len))
		err(1, "writing transaction to blockfile");
}
