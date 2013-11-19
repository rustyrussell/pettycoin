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
#include <ccan/io/io.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>

struct generator {
	struct state *state;
	struct log *log;
	struct io_conn *update, *answer;
	u8 *prev_merkles;
	void *solution;
	pid_t pid;
};

static void reap_generator(struct io_conn *conn, struct generator *gen)
{
	int status;
	struct state *state = gen->state;
	bool ok;

	if (conn == gen->update)
		gen->update = NULL;
	else if (conn == gen->answer)
		gen->answer = NULL;
	else
		abort();

	/* Wait for both to exit, then reap child. */
	if (gen->answer || gen->update)
		return;

	if (waitpid(gen->pid, &status, WNOHANG) == -1) {
		ok = false;
		log_unusual(gen->log,
			    "Waiting for generator %s %u returned %s",
			    gen->state->generate, gen->pid, strerror(errno));
	} else if (WIFSIGNALED(status)) {
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

	assert(state->gen == gen);
	state->gen = tal_free(gen);

	if (ok)
		start_generating(state);
}

static struct io_plan do_send_trans(struct io_conn *conn, struct generator *gen)
{
	assert(conn == gen->update);

	/* FIXME: When we support transactions, we'll send them off. */
	log_debug(gen->log, "Sending transactions going idle");
	return io_idle();
}

static struct io_plan send_go_byte(struct io_conn *conn, struct generator *gen)
{
	assert(conn == gen->update);

	return io_write("", 1, do_send_trans, gen);
}

static struct io_plan got_solution(struct io_conn *conn, struct generator *gen)
{
	struct block *new;
	enum protocol_error e;
	const struct protocol_double_sha *merkles;
	const u8 *prev_merkles;
	const struct protocol_block_tailer *tailer;
	struct protocol_block_header *hdr;
	struct protocol_net_hdr *nhdr = gen->solution;

	hdr = (void *)(nhdr + 1);
	e = unmarshall_block(gen->log, le32_to_cpu(nhdr->len) - sizeof(*nhdr),
			     hdr, &merkles, &prev_merkles, &tailer);
	if (e != PROTOCOL_ERROR_NONE) {
		log_broken(gen->log, "Generator %u unmarshall error %u",
			   gen->pid, e);
		return io_close();
	}

	e = check_block_header(gen->state, hdr, merkles, prev_merkles,
			       tailer, &new);
	if (e != PROTOCOL_ERROR_NONE) {
		log_broken(gen->log, "Generator %u block error %u",
			   gen->pid, e);
		return io_close();
	}

	log_info(gen->log,
		 "Solution received from generator for block %u",
		 new->blocknum);
	if (block_add(gen->state, new))
		restart_generating(gen->state);

	save_block(gen->state, new);

	/* We may need to revise what we consider mutual blocks with peers. */
 	update_peers_mutual(gen->state);

	/* FIXME: Transaction support, call put_batch_in_block()! */
	return io_close();
}

static void exec_generator(struct generator *gen)
{
	int outfd[2], infd[2];
	char difficulty[STR_MAX_CHARS(u32)], prev_merkles[STR_MAX_CHARS(u32)];
	char prevblock[sizeof(struct protocol_double_sha) * 2 + 1];
	char nonce[14];
	int i;
	size_t n_prev_merkles;
	const struct block *last;
	/* FIXME: Invalid reward address. */
	struct protocol_address my_addr = { { 0 } };
	char log_prefix[40];

	last = list_tail(&gen->state->main_chain, struct block, list);
	sprintf(difficulty, "%u", get_difficulty(gen->state, last));
	n_prev_merkles = num_prev_merkles(last);
	sprintf(prev_merkles, "%u", n_prev_merkles);
	for (i = 0; i < sizeof(struct protocol_double_sha); i++)
		sprintf(prevblock + i*2, "%02X", last->sha.sha[i]);
	
	for (i = 0; i < sizeof(nonce); i++)
		nonce[i] = 32 + isaac64_next_uint(isaac64, 224);

	gen->prev_merkles = make_prev_merkles(gen, gen->state, last, &my_addr);

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
			sleep(10);

		execlp(gen->state->generate,
		       "pettycoin-generate",
		       /* FIXME: Invalid reward address. */
		       "0000000000000000000000000000000000000000",
		       difficulty, prevblock, prev_merkles, nonce, NULL);
		exit(127);
	}

	sprintf(log_prefix, "Generator %u:", gen->pid);
	gen->log = new_log(gen, log_prefix, gen->state->log_level, GEN_LOG_MAX);
	log_debug(gen->log, "Running '%s' '%s' '%s' %s' '%s' '%s'",
		  gen->state->generate,
		  /* FIXME: Invalid reward address. */
		  "0000000000000000000000000000000000000000",
		  difficulty, prevblock, prev_merkles, nonce);

	close(outfd[1]);
	close(infd[0]);

	gen->update = io_new_conn(infd[1],
				  io_write(gen->prev_merkles, n_prev_merkles,
					   send_go_byte, gen));
	gen->answer = io_new_conn(outfd[0],
				  io_read_packet(&gen->solution, got_solution,
						 gen));
	io_set_finish(gen->update, reap_generator, gen);
	io_set_finish(gen->answer, reap_generator, gen);
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
		if (state->gen->update)
			io_close_other(state->gen->update);
	}
}
