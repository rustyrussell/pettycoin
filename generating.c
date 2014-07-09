#include "block.h"
#include "blockfile.h"
#include "chain.h"
#include "check_block.h"
#include "difficulty.h"
#include "generate.h"
#include "generating.h"
#include "log.h"
#include "marshal.h"
#include "packet_io.h"
#include "peer.h"
#include "pending.h"
#include "prev_txhashes.h"
#include "protocol_net.h"
#include "pseudorand.h"
#include "recv_block.h"
#include "state.h"
#include "tx.h"
#include <ccan/array_size/array_size.h>
#include <ccan/io/io.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>

static const struct protocol_address *generating_address(struct state *state)
{
	/* FIXME: Invalid reward address. */
	static struct protocol_address my_addr = { { 0 } };

	return &my_addr;
}

struct pending_update {
	struct list_node list;
	struct gen_update update;
};

struct solution {
	/* The solution it found. */
	struct protocol_pkt_block *block;

	unsigned int shards_read;
	/* The hashes in the shards */
	struct protocol_pkt_shard **shard;
};

struct generator {
	struct state *state;
	struct log *log;
	struct io_conn *update, *answer;
	void *pkt_in;
	pid_t pid;
	u8 shard_order;
	/* Update list. */
	struct list_head updates;

	struct solution *solution;
};

/* After both fds close, this gets called. */
static void reap_generator(struct io_conn *conn, struct generator *gen)
{
	int status;
	struct state *state = gen->state;
	bool ok;
	int ret;

	log_debug(gen->log, "Generator closed");
	assert(!gen->answer);
	assert(!gen->update);

	/* If we use WHOHANG here, we get occasional failures under
	 * load.  The implicit close on exit is done before the kernel
	 * marks the process ready to be reaped, which is fair enough.
	 * But it should only close the fd on exit anyway. */
	if ((ret = waitpid(gen->pid, &status, 0)) != gen->pid) {
		ok = false;
		log_unusual(gen->log,
			    "Waiting for generator %s %u returned %i %s",
			    gen->state->generate, gen->pid, ret, strerror(errno));
	} else if (WIFSIGNALED(status) && WTERMSIG(status) != SIGUSR1) {
		log_unusual(gen->log,
			    "generator %s %u exited with signal %u",
			    gen->state->generate, gen->pid, WTERMSIG(status));
		ok = false;
	} else if (WEXITSTATUS(status) != 0) {
		ok = false;
		log_unusual(gen->log,
			    "generator %s %u exited with status %u",
			    gen->state->generate, gen->pid, WEXITSTATUS(status));
	} else {
		ok = true;
		log_debug(gen->log, "generator %s %u exited normally",
			  gen->state->generate, gen->pid);
	}

	assert(!state->gen || state->gen == gen);
	state->gen = tal_free(gen);

	if (ok)
		start_generating(state);
}

/* Whichever fd gets closed last reaps the generator */
static void finish_update(struct io_conn *conn, struct generator *gen)
{
	assert(gen->update);
	gen->update = NULL;
	if (gen->answer)
		io_close_other(gen->answer);
	else
		reap_generator(conn, gen);
}

static void finish_answer(struct io_conn *conn, struct generator *gen)
{
	assert(gen->answer);
	gen->answer = NULL;
	if (gen->update)
		io_close_other(gen->update);
	else
		reap_generator(conn, gen);
}		       

static struct io_plan do_send_tx(struct io_conn *conn,struct generator *gen);

static struct io_plan tx_sent(struct io_conn *conn, struct generator *gen)
{
	assert(conn == gen->update);

	log_debug(gen->log, "Update done.");
	tal_free(list_pop(&gen->updates, struct pending_update, list));

	return do_send_tx(conn, gen);
}

static struct io_plan do_send_tx(struct io_conn *conn, struct generator *gen)
{
	struct pending_update *u;

	assert(conn == gen->update);

	u = list_top(&gen->updates, struct pending_update, list);
	if (u) {
		log_debug(gen->log,
			  "Sending transaction update shard %u off %u",
			  u->update.shard, u->update.txoff);

		return io_write(&u->update, sizeof(u->update), tx_sent, gen);
	}

	log_debug(gen->log, "Sending transactions going idle %p", gen);
	return io_wait(gen, do_send_tx, gen);
}

static struct io_plan send_go_byte(struct io_conn *conn, struct generator *gen)
{
	assert(conn == gen->update);

	log_debug(gen->log, "Sending go byte");
	return io_write("", 1, do_send_tx, gen);
}

static struct io_plan got_shard(struct io_conn *conn, struct generator *gen)
{
	gen->solution->shard[gen->solution->shards_read++]
		= tal_steal(gen->solution, gen->pkt_in);

	if (gen->solution->shards_read != tal_count(gen->solution->shard))
		return io_read_packet(&gen->pkt_in, got_shard, gen);

	/* We've got all the shards! */
	recv_block_from_generator(gen->state, gen->log, gen->solution->block,
				  gen->solution->shard);

	return io_close();
}

static struct io_plan got_solution(struct io_conn *conn, struct generator *gen)
{
	gen->solution = tal(gen, struct solution);
	gen->solution->block = tal_steal(gen->solution, gen->pkt_in);

	gen->solution->shard = tal_arr(gen->solution,
				       struct protocol_pkt_shard *,
				       1 << gen->shard_order);
	gen->solution->shards_read = 0;
	return io_read_packet(&gen->pkt_in, got_shard, gen);
}

/* FIXME: If transaction may go over horizon, time out generation */
static void add_update(struct state *state,
		       struct pending_tx *t,
		       size_t shard, size_t txoff)
{
	struct pending_update *update;

	update = tal(state->gen, struct pending_update);
	update->update.features = t->tx->hdr.features;
	update->update.shard = shard;
	update->update.txoff = txoff;
	update->update.unused = 0;
	hash_tx_and_refs(t->tx, t->refs, &update->update.hashes);

	/* We shouldn't overflow. */
	assert(update->update.shard == shard);
	assert(update->update.txoff == txoff);

	list_add_tail(&state->gen->updates, &update->list);
}

static void init_updates(struct generator *gen)
{
	size_t shard, i;

	list_head_init(&gen->updates);

	for (shard = 0; shard < ARRAY_SIZE(gen->state->pending->pend); shard++) {
		struct pending_tx **pend = gen->state->pending->pend[shard];
		for (i = 0; i < tal_count(pend); i++)
			add_update(gen->state, pend[i], shard, i);
	}
}

static void exec_generator(struct generator *gen)
{
	int outfd[2], infd[2];
	char difficulty[STR_MAX_CHARS(u32)],
		prev_merkle_str[STR_MAX_CHARS(u32)],
		depth[STR_MAX_CHARS(u32)],
		shard_order[STR_MAX_CHARS(u8)];
	char prevblock[sizeof(struct protocol_double_sha) * 2 + 1];
	char nonce[14 + 1];
	int i;
	const struct block *last;
	char log_prefix[40];
	const u8 *prev_txhashes = gen->state->pending->prev_txhashes;

	/* FIXME: This is where we increment shard_order if voted! */
	gen->shard_order = gen->state->longest_knowns[0]->hdr->shard_order;

	prev_txhashes = make_prev_txhashes(gen,
					   gen->state->longest_knowns[0],
					   generating_address(gen->state));
	last = gen->state->longest_knowns[0];
	sprintf(difficulty, "%u", get_difficulty(gen->state, last));
	sprintf(prev_merkle_str, "%zu", tal_count(prev_txhashes));
	sprintf(depth, "%u", le32_to_cpu(last->hdr->depth) + 1);
	sprintf(shard_order, "%u", gen->shard_order);
	for (i = 0; i < sizeof(struct protocol_double_sha); i++)
		sprintf(prevblock + i*2, "%02X", last->sha.sha[i]);
	
	for (i = 0; i < sizeof(nonce)-1; i++)
		nonce[i] = 32 + isaac64_next_uint(isaac64, 224);
	nonce[i] = '\0';

	if (pipe(outfd) != 0 || pipe(infd) != 0)
		fatal(gen->state, "pipe: %s", strerror(errno));

	gen->pid = fork();
	if (gen->pid == -1)
		fatal(gen->state, "fork: %s", strerror(errno));

	if (gen->pid == 0) {
		close(outfd[0]);
		close(infd[1]);
		dup2(outfd[1], STDOUT_FILENO);
		dup2(infd[0], STDIN_FILENO);

		/* Make sure timestamp moves forward! */
		if (gen->state->developer_test)
			sleep(5 + isaac64_next_uint(isaac64, 10));

		execlp(gen->state->generate,
		       "pettycoin-generate",
		       /* FIXME: Invalid reward address. */
		       "0000000000000000000000000000000000000000",
		       difficulty, prevblock, prev_merkle_str,
		       depth, shard_order, nonce, NULL);
		exit(127);
	}

	sprintf(log_prefix, "Generator %u:", gen->pid);
	gen->log = new_log(gen, gen->state->log,
			   log_prefix, gen->state->log_level, GEN_LOG_MAX);
	log_debug(gen->log, "Running '%s' '%s' '%s' '%s' %s' '%s' '%s' '%s'",
		  gen->state->generate,
		  /* FIXME: Invalid reward address. */
		  "0000000000000000000000000000000000000000",
		  difficulty, prevblock, prev_merkle_str, depth, shard_order,
		  nonce);

	close(outfd[1]);
	close(infd[0]);

	init_updates(gen);
	gen->update = io_new_conn(infd[1],
				  io_write(prev_txhashes,
					   tal_count(prev_txhashes)*sizeof(u8),
					   send_go_byte, gen));
	io_set_finish(gen->update, finish_update, gen);
	gen->answer = io_new_conn(outfd[0],
				  io_read_packet(&gen->pkt_in, got_solution,
						 gen));
	io_set_finish(gen->answer, finish_answer, gen);
}

/* state->pending->t[shard][txoff] has been added. */
void tell_generator_new_pending(struct state *state, u32 shard, u32 txoff)
{
	/* Tell generator about new transaction. */
	if (!state->gen)
		return;

	add_update(state, state->pending->pend[shard][txoff], shard, txoff);
	io_wake(state->gen);
}

/* FIXME: multiple generators. */
void start_generating(struct state *state)
{
	state->gen = tal(state, struct generator);
	state->gen->state = state;

	exec_generator(state->gen);
}

void restart_generating(struct state *state)
{
	/* Shut down existing generator, will restart after reaping. */
	if (state->gen) {
		log_debug(state->gen->log, "shutdown due to restart");
		/* This should make the generator shutdown. */
		kill(state->gen->pid, SIGUSR1);
		/* Don't restart again before it's reaped. */
		state->gen = NULL;
	}
}
