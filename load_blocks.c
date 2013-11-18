#include "protocol_net.h"
#include "state.h"
#include "marshall.h"
#include "check_block.h"
#include "block.h"
#include "load_blocks.h"
#include "packet.h"
#include <ccan/err/err.h>
#include <ccan/io/io.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

static bool get_block(struct state *state, struct protocol_net_hdr *pkt)
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

void load_blocks(struct state *state)
{
	off_t off = 0;
	struct stat st;

	state->blockfd = open("blocks.list", O_RDWR|O_CREAT, 0600);
	if (state->blockfd < 0)
		err(1, "Opening blocks.list");

	for (;;) {
		struct protocol_net_hdr *pkt;
		struct io_plan plan;
		int ret;

		plan = io_read_packet_(&pkt, NULL, NULL);
		while ((ret = plan.io(state->blockfd, &plan)) != 1) {
			if (ret == -1) {
				/* Did we do a partial read? */
				if (lseek(state->blockfd, SEEK_CUR, 0) != off)
					goto truncate;
				return;
			}
		}

		switch (le32_to_cpu(pkt->type)) {
		case PROTOCOL_REQ_NEW_BLOCK:
			if (!get_block(state, pkt)) {
				log_unusual(state->log,
					    "blocks.list partial block");
				goto truncate;
			}
		default:
			log_unusual(state->log, "blocks.list unknown type %u",
				    le32_to_cpu(pkt->type));
			goto truncate;
		}
		off += le32_to_cpu(pkt->len);
	}

truncate:
	fstat(state->blockfd, &st);
	log_unusual(state->log, "blocks.list truncated from %llu to %llu",
		    (long long)off, (long long)st.st_size);
	ftruncate(state->blockfd, off);
}

void save_block(struct state *state, struct block *new)
{
	struct protocol_req_new_block *blk;
	size_t len;

	blk = marshall_block(state,
			     new->hdr, new->merkles, new->prev_merkles,
			     new->tailer);
	len = le32_to_cpu(blk->len);
	if (write(state->blockfd, blk, len) != len)
		errx(1, "short write to blocks.list");

	tal_free(blk);
}
