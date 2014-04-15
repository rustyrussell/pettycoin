#include "generating.h"
#include "difficulty.h"
#include "state.h"
#include "log.h"
#include "pseudorand.h"
#include "protocol_net.h"
#include "marshall.h"
#include "check_block.h"
#include "block.h"
#include "prev_merkles.h"
#include "packet.h"
#include "peer.h"
#include "blockfile.h"
#include "generate.h"
#include "pending.h"
#include <ccan/io/io.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>

static const struct protocol_address *generating_address(struct state *state)
{
	/* FIXME: Invalid reward address. */
	static struct protocol_address my_addr = { { 0 } };

	return &my_addr;
}

struct pending_update {
	struct list_node list;
	struct update update;
};

struct generator {
	struct state *state;
	struct log *log;
	struct io_conn *update, *answer;
	void *pkt_in;
	/* The block it found. */
	struct block *new;
	/* The transactions it included. */
	union protocol_transaction **trans;
	pid_t pid;
	/* Update list. */
	struct list_head updates;
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

static struct io_plan do_send_trans(struct io_conn *conn,struct generator *gen);

static struct io_plan trans_sent(struct io_conn *conn, struct generator *gen)
{
	assert(conn == gen->update);

	log_debug(gen->log, "Update done.");
	tal_free(list_pop(&gen->updates, struct pending_update, list));

	return do_send_trans(conn, gen);
}

static struct io_plan do_send_trans(struct io_conn *conn, struct generator *gen)
{
	struct pending_update *u;

	assert(conn == gen->update);

	u = list_top(&gen->updates, struct pending_update, list);
	if (u) {
		log_debug(gen->log, "Sending transaction update pos %u cookie %p",
			  u->update.trans_idx, u->update.cookie);

		return io_write(&u->update, sizeof(u->update), trans_sent, gen);
	}

	log_debug(gen->log, "Sending transactions going idle %p", gen);
	return io_wait(gen, do_send_trans, gen);
}

static struct io_plan send_go_byte(struct io_conn *conn, struct generator *gen)
{
	assert(conn == gen->update);

	log_debug(gen->log, "Sending go byte");
	return io_write("", 1, do_send_trans, gen);
}

static struct io_plan got_trans(struct io_conn *conn, struct generator *gen)
{
	u32 i, num_trans;

	/* Break into batches, and add. */
	num_trans = le32_to_cpu(gen->new->hdr->num_transactions);

	log_debug(gen->log, "Got %u transactions", num_trans);
	for (i = 0; i < num_trans; i += (1 << PETTYCOIN_BATCH_ORDER)) {
		struct transaction_batch *b;
		u32 num = num_trans - i;

		if (num > (1 << PETTYCOIN_BATCH_ORDER))
			num = (1 << PETTYCOIN_BATCH_ORDER);

		b = talz(gen, struct transaction_batch);
		b->trans_start = i;
		b->count = num;
		memcpy(b->t, gen->trans + i, num * sizeof(b->t[0]));

		if (!check_batch_valid(gen->state, gen->new, b)) {
			log_broken(gen->log,
				   "Generator %u created invalid batch %u-%u",
				   gen->pid, i, i+num);
			return io_close();
		}
		if (!put_batch_in_block(gen->state, gen->new, b)) {
			log_broken(gen->log,
				   "Generator %u created unusable batch %u-%u",
				   gen->pid, i, i+num);
			return io_close();
		}
		log_debug(gen->log, "Added batch %u-%u", i, i+num);
	}

	/* Ignore return: we restart generating whether this is in main chain or not */
	assert(block_full(gen->new, NULL));
	block_add(gen->state, gen->new);
	save_block(gen->state, gen->new);

	for (i = 0; i < num_trans; i++)
		save_transaction(gen->state, gen->new, i);

	/* We may need to revise what we consider mutual blocks with peers. */
 	wake_peers(gen->state);

	return io_close();
}

static struct io_plan got_solution(struct io_conn *conn, struct generator *gen)
{
	enum protocol_error e;
	const struct protocol_double_sha *merkles;
	const u8 *prev_merkles;
	const struct protocol_block_tailer *tailer;
	struct protocol_block_header *hdr;
	struct protocol_net_hdr *nhdr = gen->pkt_in;

	hdr = (void *)(nhdr + 1);
	e = unmarshall_block(gen->log, le32_to_cpu(nhdr->len) - sizeof(*nhdr),
			     hdr, &merkles, &prev_merkles, &tailer);
	if (e != PROTOCOL_ERROR_NONE) {
		log_broken(gen->log, "Generator %u unmarshall error %u",
			   gen->pid, e);
		return io_close();
	}

	e = check_block_header(gen->state, hdr, merkles, prev_merkles,
			       tailer, &gen->new);
	if (e != PROTOCOL_ERROR_NONE) {
		log_broken(gen->log, "Generator %u block error %u",
			   gen->pid, e);
		return io_close();
	}

	log_info(gen->log,
		 "Solution received from generator for block %u (%u trans)",
		 gen->new->blocknum, le32_to_cpu(hdr->num_transactions));

	/* Actually check the previous merkles are correct. */
	if (!check_block_prev_merkles(gen->state, gen->new)) {
		log_broken(gen->log,
			   "Generator %u block %u bad prev_merkles",
			   gen->pid, gen->new->blocknum);
		return io_close();
	}
	/* Read transaction pointers back. */
	gen->trans = tal_arr(gen, union protocol_transaction *,
			     le32_to_cpu(hdr->num_transactions));

	return io_read(gen->trans, sizeof(union protocol_transaction *)
		       * le32_to_cpu(hdr->num_transactions), got_trans, gen);
}

static void init_updates(struct generator *gen)
{
	size_t i;
	const union protocol_transaction **t = gen->state->pending->t;

	list_head_init(&gen->updates);

	for (i = 0; i < tal_count(t); i++) {
		struct pending_update *update;

		update = tal(gen, struct pending_update);
		update->update.features = t[i]->hdr.features;
		update->update.trans_idx = i;
		update->update.cookie = t[i];
		hash_transaction(t[i], NULL, 0, &update->update.hash);
		list_add_tail(&gen->updates, &update->list);
	}
}

static void exec_generator(struct generator *gen)
{
	int outfd[2], infd[2];
	char difficulty[STR_MAX_CHARS(u32)],
		prev_merkle_str[STR_MAX_CHARS(u32)];
	char prevblock[sizeof(struct protocol_double_sha) * 2 + 1];
	char nonce[14 + 1];
	int i;
	const struct block *last;
	char log_prefix[40];
	const u8 *prev_merkles = gen->state->pending->prev_merkles;

	prev_merkles = make_prev_merkles(gen, gen->state,
					 gen->state->longest_known,
					 generating_address(gen->state));
	last = gen->state->longest_known;
	sprintf(difficulty, "%u", get_difficulty(gen->state, last));
	sprintf(prev_merkle_str, "%zu", tal_count(prev_merkles));
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
		       difficulty, prevblock, prev_merkle_str, nonce, NULL);
		exit(127);
	}

	sprintf(log_prefix, "Generator %u:", gen->pid);
	gen->log = new_log(gen, gen->state->log,
			   log_prefix, gen->state->log_level, GEN_LOG_MAX);
	log_debug(gen->log, "Running '%s' '%s' '%s' %s' '%s' '%s'",
		  gen->state->generate,
		  /* FIXME: Invalid reward address. */
		  "0000000000000000000000000000000000000000",
		  difficulty, prevblock, prev_merkle_str, nonce);

	close(outfd[1]);
	close(infd[0]);

	init_updates(gen);
	gen->update = io_new_conn(infd[1],
				  io_write(prev_merkles,
					   tal_count(prev_merkles) * sizeof(u8),
					   send_go_byte, gen));
	io_set_finish(gen->update, finish_update, gen);
	gen->answer = io_new_conn(outfd[0],
				  io_read_packet(&gen->pkt_in, got_solution,
						 gen));
	io_set_finish(gen->answer, finish_answer, gen);
}

void tell_generator_new_pending(struct state *state, unsigned int num)
{
	struct pending_update *update;
	const union protocol_transaction *t;

	/* Tell generator about new transaction. */
	if (!state->gen)
		return;

	/* This is the new transaction. */
	t = state->pending->t[num];

	update = tal(state->gen, struct pending_update);
	update->update.features = t->hdr.features;
	update->update.trans_idx = num;
	update->update.cookie = t;
	hash_transaction(t, NULL, 0, &update->update.hash);
	list_add_tail(&state->gen->updates, &update->list);
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
