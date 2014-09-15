#include "block.h"
#include "blockfile.h"
#include "chain.h"
#include "check_block.h"
#include "marshal.h"
#include "packet_io.h"
#include "proof.h"
#include "protocol_net.h"
#include "recv_block.h"
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
	const u8 *num_txs;
	const struct protocol_double_sha *merkles;
	const u8 *prev_txhashes;
	const struct protocol_block_tailer *tailer;
	const struct protocol_block_header *hdr;
	struct protocol_block_id sha;

	e = unmarshal_block(state->log, (void *)pkt,
			    &hdr, &num_txs, &merkles, &prev_txhashes,
			    &tailer);
	if (e != PROTOCOL_ECODE_NONE)
		return false;

	e = check_block_header(state, hdr, num_txs, merkles, prev_txhashes,
			       tailer, &prev, &sha.sha);
	if (e != PROTOCOL_ECODE_NONE)
		return false;

	block = block_add(state, prev, &sha,
			  hdr, num_txs, merkles, prev_txhashes, tailer);

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

struct load_state {
	struct state *state;
	off_t processed;
	struct protocol_net_hdr *pkt;
};

static struct io_plan *load_packet(struct io_conn *conn, struct load_state *ls)
{
	switch (le32_to_cpu(ls->pkt->type)) {
	case PROTOCOL_PKT_BLOCK:
		if (!load_block(ls->state, ls->pkt)) {
			log_unusual(ls->state->log,
				    "blockfile partial block");
			return io_close(conn);
		}
		break;
	case PROTOCOL_PKT_TX_IN_BLOCK:
		if (!load_tx_in_block(ls->state, (const void *)ls->pkt)) {
			log_unusual(ls->state->log,
				    "blockfile partial transaction");
			return io_close(conn);
		}
		break;
	default:
		log_unusual(ls->state->log, "blockfile unknown type %u",
			    le32_to_cpu(ls->pkt->type));
		return io_close(conn);
	}

	ls->processed = lseek(io_conn_fd(conn), 0, SEEK_CUR);
	return io_read_packet(conn, &ls->pkt, load_packet, ls);
}

static struct io_plan *setup_load_conn(struct io_conn *conn,
				       struct load_state *ls)
{
	return io_read_packet(conn, &ls->pkt, load_packet, ls);
}

/* This can happen if we didn't know some TXs when we exited. */
static void get_unknown_contents(struct state *state)
{
	unsigned int i;
	const struct block *b;

	for (i = 0; i < tal_count(state->longest_chains); i++) {
		for (b = state->longest_chains[i]; b; b = b->prev) {
			/* Stop if we know from here down. */
			if (b->all_known)
				break;

			get_block_contents(state, b);
		}
	}
}

void load_blocks(struct state *state)
{
	int fd;
	struct load_state ls;
	off_t len;

	fd = open("blockfile", O_RDWR|O_CREAT, 0600);
	if (fd < 0)
		err(1, "Opening blockfile");

	/* Prevent us saving blocks as we're reading them. */
	state->blockfd = -1;

	ls.state = state;
	ls.processed = 0;
	io_new_conn(state, fd, setup_load_conn, &ls);

	/* When it reads 0 bytes, it will close, so dup fd. */
	fd = dup(fd);

	/* Process them all. */
	io_loop(NULL, NULL);

	len = lseek(fd, 0, SEEK_END);
	/* If we didn't process the entire file, truncate it. */
	if (len != ls.processed) {
		log_unusual(state->log,
			    "Truncating blockfile from %llu to %llu",
			    (long long)len, (long long)ls.processed);
		ftruncate(fd, ls.processed);
		lseek(fd, SEEK_SET, ls.processed);
	}

	/* Now we can save more. */
	state->blockfd = fd;

	log_info(state->log, "Checking chains...");
	check_chains(state, true);
	log_add(state->log, " ...completed");

	/* If there are any txs we want to know and don't, ask. */
	get_unknown_contents(state);
}

void save_block(struct state *state, struct block *new)
{
	struct protocol_pkt_block *blk;
	size_t len;

	/* Don't save while we're still loading. */
	if (state->blockfd == -1)
		return;

	blk = marshal_block(state,
			    new->hdr, new->num_txs, new->merkles,
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
