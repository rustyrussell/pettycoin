#include "peer.h"
#include "state.h"
#include "protocol_net.h"
#include "packet.h"
#include "dns.h"
#include "netaddr.h"
#include "welcome.h"
#include "peer_cache.h"
#include "block.h"
#include "log.h"
#include "marshall.h"
#include "check_block.h"
#include "check_transaction.h"
#include "generating.h"
#include "blockfile.h"
#include "pending.h"
#include "merkle_transactions.h"
#include <ccan/io/io.h>
#include <ccan/time/time.h>
#include <ccan/tal/tal.h>
#include <ccan/tal/path/path.h>
#include <ccan/err/err.h>
#include <ccan/build_assert/build_assert.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define MIN_PEERS 16

struct peer_lookup {
	struct state *state;
	void *pkt;
};

static struct io_plan digest_peer_addrs(struct io_conn *conn,
					struct peer_lookup *lookup)
{
	le32 *len = lookup->pkt;
	u32 num, i;
	struct protocol_net_address *addr;

	num = (le32_to_cpu(*len) - sizeof(struct protocol_net_hdr))
	       / sizeof(*addr);
	/* Addresses are after header (which includes unused type field). */
	addr = (void *)(len + 2);

	log_debug(lookup->state->log,
		  "seed server supplied %u peers in %u bytes",
		  num, le32_to_cpu(*len));
	for (i = 0; i < num; i++) {
		log_debug(lookup->state->log, "Adding address to peer cache: ");
		log_add_struct(lookup->state->log,
			       struct protocol_net_address, &addr[i]);
		peer_cache_add(lookup->state, &addr[i]);
	}

	/* We can now get more from cache. */
	fill_peers(lookup->state);

	return io_close();
}

static struct io_plan read_seed_peers(struct io_conn *conn,
				      struct state *state)
{
	struct peer_lookup *lookup = tal(conn, struct peer_lookup);

	log_debug(state->log, "Connected to seed server, reading peers");
	lookup->state = state;
	return io_read_packet(&lookup->pkt, digest_peer_addrs, lookup);
}

/* This gets called when the connection closes, fail or success. */
static void unset_peer_seeding(struct state **statep)
{
	log_debug((*statep)->log, "Seeding connection closed");
	(*statep)->peer_seeding = false;
	fill_peers(*statep);
}

static void seed_peers(struct state *state)
{
	const char *server = "peers.pettycoin.org";
	tal_t *connector;

	/* Don't grab more if we're already doing that. */
	if (state->peer_seeding) {
		log_debug(state->log, "Seeding ongoing already");
		return;
	}

	if (state->peer_seed_count++ > 2) {
		if (state->developer_test)
			return;

		fatal(state, "Failed to connect to any peers, or peer server");
	}

	if (state->developer_test)
		server = "localhost";

	connector = dns_resolve_and_connect(state, server, "9000",
					    read_seed_peers);
	if (!connector) {
		log_unusual(state->log, "Could not connect to %s", server);
	} else {
		/* Temporary allocation, to get destructor called. */
		struct state **statep = tal(connector, struct state *);
		state->peer_seeding = true;
		(*statep) = state;
		tal_add_destructor(statep, unset_peer_seeding);

		log_debug(state->log, "Connecting to seed server %s", server);
	}
}

void fill_peers(struct state *state)
{
	if (!state->refill_peers)
		return;

	while (state->num_peers < MIN_PEERS) {
		struct protocol_net_address *a;
		int fd;

		a = read_peer_cache(state);
		if (!a) {
			log_debug(state->log, "Seeding peer cache");
			seed_peers(state);
			break;
		}
		fd = socket_for_addr(a);

		/* Maybe we don't speak IPv4/IPv6? */
		if (fd == -1) {
			log_unusual(state->log, "Creating socket failed for ");
			log_add_struct(state->log,
				       struct protocol_net_address, a);
			log_add(state->log, ": %s", strerror(errno));
			peer_cache_del(state, a, true);
		} else {
			new_peer(state, fd, a);
		}
	}
}

struct pending_trans {
	struct list_node list;
	const union protocol_transaction *t;
};

void remove_trans_from_peers(struct state *state,
			     const union protocol_transaction *t)
{
	struct peer *p;

	list_for_each(&state->peers, p, list) {
		struct pending_trans *pend;

		list_for_each(&p->pending, pend, list) {
			if (pend->t == t) {
				/* Destructor removes from list. */
				tal_free(pend);
				break;
			}
		}
	}
}

static void unlink_pend(struct pending_trans *pend)
{
	list_del(&pend->list);
}
	
void add_trans_to_peers(struct state *state,
			struct peer *exclude,
			const union protocol_transaction *t)
{
	struct peer *peer;

	list_for_each(&state->peers, peer, list) {
		struct pending_trans *pend;

		/* Avoid sending back to peer who told us. */
		if (peer == exclude)
			continue;

		pend = tal(peer, struct pending_trans);
		pend->t = t;
		list_add_tail(&peer->pending, &pend->list);
		tal_add_destructor(pend, unlink_pend);
		/* In case it's idle. */
		io_wake(peer);
	}
}

struct complaint {
	struct list_node list;
	const struct protocol_net_hdr *pkt;
};

static void add_complaint(struct peer *peer,
			  const struct protocol_net_hdr *pkt)
{
	struct complaint *c = tal(NULL, struct complaint);
	list_add_tail(&peer->complaints, &c->list);

	c->pkt = (void *)tal_dup(peer, char, (char *)pkt,
				 le32_to_cpu(pkt->len), 0);
	/* Free complaint structure when packet freed. */
	tal_steal(c->pkt, c);
}

void complain_to_peers(struct state *state, const struct protocol_net_hdr *pkt)
{
	struct peer *peer;

	list_for_each(&state->peers, peer, list)
		add_complaint(peer, pkt);
}

static struct protocol_req_err *protocol_req_err(struct peer *peer,
						 enum protocol_error e)
{
	struct protocol_req_err *pkt;

	pkt = tal_packet(peer, struct protocol_req_err, PROTOCOL_REQ_ERR);
	pkt->error = cpu_to_le32(e);

	return pkt;
}

static struct protocol_resp_err *protocol_resp_err(struct peer *peer,
						   enum protocol_error e)
{
	struct protocol_resp_err *pkt;

	pkt = tal_packet(peer, struct protocol_resp_err, PROTOCOL_RESP_ERR);
	pkt->error = cpu_to_le32(e);

	return pkt;
}

/* They've told us about a block; this implies they know it. */
static void update_mutual(struct peer *peer, struct block *block)
{
	/* If the block is known bad, tell them! */
	if (block->complaint) {
		add_complaint(peer, block->complaint);
		return;
	}

	/* Don't go backwards. */
	if (block_preceeds(block, peer->mutual))
		return;
	   
	/* Don't update if it would take us away from our preferred chain */
	if (!block_preceeds(block, peer->state->longest_known_descendent))
		return;

	peer->mutual = block;
}

static struct block *mutual_block_search(struct peer *peer,
					 const struct protocol_double_sha *block,
					 u32 num_blocks)
{
	int i;

	for (i = 0; i < num_blocks; i++) {
		struct block *b = block_find_any(peer->state, &block[i]);

		log_debug(peer->log, "Seeking mutual block ");
		log_add_struct(peer->log, struct protocol_double_sha, &block[i]);
		if (b) {
			log_add(peer->log, " found.");
			return b;
		}
		log_add(peer->log, " not found.");
	}
	return NULL;
}

static struct io_plan plan_output(struct io_conn *conn, struct peer *peer);

/* Blockchain has been extended/changed. */
void wake_peers(struct state *state)
{
	struct peer *p;

	list_for_each(&state->peers, p, list)
		io_wake(p);
}

static struct protocol_req_new_block *block_pkt(tal_t *ctx, struct block *b)
{
	struct protocol_req_new_block *blk;
 
	blk = marshall_block(ctx,
			     b->hdr, b->merkles, b->prev_merkles, b->tailer);

	return blk;
}

static struct protocol_req_batch *batch_req(tal_t *ctx, struct block *b,
					    unsigned int batchnum)
{
	struct protocol_req_batch *r;
 
	r = tal_packet(ctx, struct protocol_req_batch, PROTOCOL_REQ_BATCH);
	r->block = b->sha;
	r->batchnum = cpu_to_le32(batchnum);

	return r;
}

static struct protocol_req_new_transaction *
trans_pkt(tal_t *ctx, const union protocol_transaction *t)
{
	struct protocol_req_new_transaction *r;
	r = tal_packet(ctx, struct protocol_req_new_transaction,
		       PROTOCOL_REQ_NEW_TRANSACTION);

	tal_packet_append_trans(&r, t);
	return r;
}

static struct io_plan response_sent(struct io_conn *conn, struct peer *peer)
{
	/* We sent a response, now we're ready for another request. */
	peer->response = NULL;
	peer->curr_in_req = PROTOCOL_REQ_NONE;
	return plan_output(conn, peer);
}

/* We tell everyone about our preferred chain. */
static struct block *get_next_mutual_block(struct peer *peer)
{
	return step_towards(peer->mutual, peer->state->longest_known_descendent);
}

static struct io_plan plan_output(struct io_conn *conn, struct peer *peer)
{
	struct block *next;
	struct pending_trans *pend;
	struct complaint *complaint;
	const void *pkt;

	/* There was an error?  Send that then close. */
	if (peer->error_pkt) {
		log_debug(peer->log, "Writing error packet ");
		log_add_enum(peer->log, enum protocol_resp_type,
			     ((struct protocol_net_hdr *)peer->error_pkt)->type);
		log_add_enum(peer->log, enum protocol_error,
			     ((struct protocol_resp_err *)peer->error_pkt)->error);
		return io_write_packet(peer, peer->error_pkt, io_close_cb);
	}

	/* First, respond to their queries. */
	if (peer->response) {
		log_debug(peer->log, "Writing response packet ");
		log_add_enum(peer->log, enum protocol_resp_type,
			     ((struct protocol_net_hdr *)peer->response)->type);
		return io_write_packet(peer, peer->response, response_sent);
	}

	/* Are we waiting for a response? */
	if (peer->curr_out_req != PROTOCOL_REQ_NONE) {
		log_debug(peer->log, "Awaiting response packet");
		return io_wait(peer, plan_output, peer);
	}

	/* Have we found a problem, using knowledge of other trans? */
	complaint = list_pop(&peer->complaints, struct complaint,list);
	if (complaint) {
		log_debug(peer->log, "Writing complaint packet ");
		log_add_enum(peer->log, enum protocol_req_type,
			     le32_to_cpu(complaint->pkt->type));
		peer->curr_out_req = le32_to_cpu(complaint->pkt->type);
		pkt = complaint->pkt;
		goto write;
	}

	/* Second, do we have any blocks to send? */
	next = get_next_mutual_block(peer);
	if (next) {
		log_debug(peer->log, "Sending block %u", next->blocknum);
		peer->curr_out_req = PROTOCOL_REQ_NEW_BLOCK;
		peer->mutual = next;
		pkt = block_pkt(peer, next);
		goto write;
	}

	/* Can we find more about longest known chain? */
	next = step_towards(peer->state->longest_known,
			    peer->state->longest_chain);
	if (next) {
		unsigned int batchnum;

		/* This must not be full, or it would be longest known. */
		if (block_full(next, &batchnum))
			abort();

		log_debug(peer->log, "Need batch %u for block %u toward longest",
			  batchnum, next->blocknum);
		peer->curr_out_req = PROTOCOL_REQ_BATCH;
		peer->batch_requested_block = next;
		peer->batch_requested_num = batchnum;
		pkt = batch_req(peer, next, batchnum);
		goto write;
	}

	/* Can we find more about longest descendent of known chain? */
	next = step_towards(peer->state->longest_known,
			    peer->state->longest_known_descendent);
	if (next) {
		unsigned int batchnum;

		/* This must not be full, or it would be longest known. */
		if (block_full(next, &batchnum))
			abort();

		log_debug(peer->log, "Need batch %u for block %u from known",
			  batchnum, next->blocknum);
		peer->curr_out_req = PROTOCOL_REQ_BATCH;
		peer->batch_requested_block = next;
		peer->batch_requested_num = batchnum;
		pkt = batch_req(peer, next, batchnum);
		goto write;
	}

	/* Tell them about transactions we know about */
	pend = list_pop(&peer->pending, struct pending_trans, list);
	if (pend) {
		tal_del_destructor(pend, unlink_pend);

		log_debug(peer->log, "Sending transaction ");
		log_add_struct(peer->log, union protocol_transaction, pend->t);
		peer->new_trans_pending = pend;
		peer->curr_out_req = PROTOCOL_REQ_NEW_TRANSACTION;
		pkt = trans_pkt(peer, pend->t);
		goto write;
	}

	/* Otherwise, we're idle. */
	log_debug(peer->log, "Nothing to send");
	return io_wait(peer, plan_output, peer);

write:
	log_debug(peer->log, "Sending ");
	log_add_enum(peer->log, enum protocol_req_type,
		     ((struct protocol_net_hdr *)pkt)->type);
	assert(peer->curr_out_req);
	return io_write_packet(peer, pkt, plan_output);
}

/* Returns an error packet if there was trouble. */
static struct protocol_resp_err *
receive_block(struct peer *peer, const struct protocol_req_new_block *req)
{
	struct block *new, *b;
	enum protocol_error e;
	const struct protocol_double_sha *merkles;
	const u8 *prev_merkles;
	const struct protocol_block_tailer *tailer;
	struct protocol_resp_new_block *r;
	const struct protocol_block_header *hdr = (void *)req->block;
	u32 blocklen = le32_to_cpu(req->len) - sizeof(struct protocol_net_hdr);

	e = unmarshall_block(peer->log, blocklen, hdr,
			     &merkles, &prev_merkles, &tailer);
	if (e != PROTOCOL_ERROR_NONE) {
		log_unusual(peer->log, "unmarshalling new block gave %u", e);
		goto fail;
	}

	log_debug(peer->log, "version = %u, features = %u, num_transactions = %u",
		  hdr->version, hdr->features_vote, hdr->num_transactions);

	e = check_block_header(peer->state, hdr, merkles, prev_merkles,
			       tailer, &new);
	if (e != PROTOCOL_ERROR_NONE) {
		log_unusual(peer->log, "checking new block gave %u", e);
		goto fail;
	}

	/* Now new block owns the packet. */
	tal_steal(new, req);

	/* Actually check the previous merkles are correct. */
	if (!check_block_prev_merkles(peer->state, new)) {
		log_unusual(peer->log, "new block has bad prev merkles");
		e = PROTOCOL_ERROR_BAD_PREV_MERKLES;
		/* FIXME: provide proof. */
		goto fail;
	}

	log_debug(peer->log, "New block %u is good!", new->blocknum);

	if ((b = block_find_any(peer->state, &new->sha)) != NULL) {
		log_debug(peer->log, "already knew about block %u",
			  new->blocknum);
		tal_free(new);
	} else {
		block_add(peer->state, new);
		save_block(peer->state, new);
		wake_peers(peer->state);
		b = new;
	}

	/* They obviously know about this block. */
	update_mutual(peer, new);

	/* FIXME: Try to guess the batches */

	/* Reply, tell them we're all good... */
	r = tal_packet(peer, struct protocol_resp_new_block,
		       PROTOCOL_RESP_NEW_BLOCK);
	r->final = peer->state->longest_chain->sha;

	assert(!peer->response);
	peer->response = r;
	return NULL;

fail:
	return protocol_resp_err(peer, e);
}

static void
complain_about_input(struct state *state,
		     struct peer *peer,
		     const union protocol_transaction *trans,
		     const union protocol_transaction *bad_input,
		     unsigned int bad_input_num)
{
	struct protocol_req_bad_trans_input *pkt;

	/* FIXME: We do this since we expect perfect knowledge
	   (unknown input).  We can't prove anything is wrong in this
	   case though! */
	if (!bad_input)
		return;

	pkt = tal_packet(peer, struct protocol_req_bad_trans_input,
			 PROTOCOL_REQ_BAD_TRANS_INPUT);
	pkt->inputnum = cpu_to_le32(bad_input_num);

	tal_packet_append_trans(&pkt, trans);
	tal_packet_append_trans(&pkt, bad_input);

	/* Makes copy. */
	add_complaint(peer, (struct protocol_net_hdr *)pkt);
	tal_free(pkt);
}

static void
complain_about_inputs(struct state *state,
		      struct peer *peer,
		      const union protocol_transaction *trans)
{
	struct protocol_req_bad_trans_amount *pkt;
	unsigned int i;

	assert(le32_to_cpu(trans->hdr.type) == TRANSACTION_NORMAL);

	pkt = tal_packet(peer, struct protocol_req_bad_trans_amount,
			 PROTOCOL_REQ_BAD_TRANS_AMOUNT);

	tal_packet_append_trans(&pkt, trans);

	/* FIXME: What if input still pending, not in thash? */
	for (i = 0; i < le32_to_cpu(trans->normal.num_inputs); i++) {
		union protocol_transaction *input;
		input = thash_gettrans(&state->thash,
				       &trans->normal.input[i].input);
		tal_packet_append_trans(&pkt, input);
	}

	/* Makes copy. */
	add_complaint(peer, (struct protocol_net_hdr *)pkt);
	tal_free(pkt);
}

/* Returns an error packet if there was trouble. */
static struct protocol_resp_new_transaction *
receive_trans(struct peer *peer,
	      const struct protocol_req_new_transaction *req)
{
	enum protocol_error e;
	struct protocol_resp_new_transaction *r;
	union protocol_transaction *trans;
	u32 translen = le32_to_cpu(req->len) - sizeof(*req);
	union protocol_transaction *inputs[TRANSACTION_MAX_INPUTS];
	unsigned int bad_input_num;

	r = tal_packet(peer, struct protocol_resp_new_transaction,
		       PROTOCOL_RESP_NEW_TRANSACTION);

	trans = (void *)(req + 1);
	e = unmarshall_transaction(trans, translen, NULL);
	if (e)
		goto fail;

	e = check_transaction(peer->state, trans, inputs, &bad_input_num);

	r->error = cpu_to_le32(e);

	if (e == PROTOCOL_ERROR_TRANS_BAD_INPUT) {
		/* Complain, but don't hang up on them! */
		complain_about_input(peer->state, peer, trans,
				     inputs[bad_input_num], bad_input_num);
		goto ok;
	} else if (e == PROTOCOL_ERROR_TRANS_BAD_AMOUNTS) {
		complain_about_inputs(peer->state, peer, trans);
		goto ok;
	} else if (e) {
		/* Any other failure is something they should know */
		goto fail;
	}

	/* OK, we own it now. */
	tal_steal(peer->state, req);
	add_pending_transaction(peer, trans);

ok:
	assert(!peer->response);
	peer->response = r;
	return NULL;

fail:
	r->error = cpu_to_le32(e);
	return r;
}

/* Returns an error packet if there was trouble. */
static struct protocol_resp_batch *
receive_batch_req(struct peer *peer,
		  const struct protocol_req_batch *req)
{
	struct protocol_resp_batch *r;
	struct block *block;
	struct transaction_batch *batch;
	unsigned int i, num;

	if (le32_to_cpu(req->len) != sizeof(*req))
		return (void *)protocol_resp_err(peer, PROTOCOL_INVALID_LEN);

	r = tal_packet(peer, struct protocol_resp_batch,
		       PROTOCOL_RESP_BATCH);
	r->num = 0;

	/* This could happen, but is unusual. */
	block = block_find_any(peer->state, &req->block);
	if (!block) {
		log_unusual(peer->log,
			    "Peer asked PROTOCOL_REQ_BATCH for unknown block ");
		log_add_struct(peer->log, struct protocol_double_sha,
			       &req->block);
		r->error = cpu_to_le32(PROTOCOL_ERROR_UNKNOWN_BLOCK);
		return r;
	}

	/* Obviously they know about this block. */
	update_mutual(peer, block);

	/* This should never happen. */
	num = le32_to_cpu(req->batchnum);
	if (num >= num_merkles(le32_to_cpu(block->hdr->num_transactions))) {
		log_unusual(peer->log,
			    "Peer sent PROTOCOL_RESP_BATCH for batch %u/%zu of ",
			num,
			num_merkles(le32_to_cpu(block->hdr->num_transactions)));
		log_add_struct(peer->log, struct protocol_double_sha,
			       &req->block);
		r->error = cpu_to_le32(PROTOCOL_ERROR_BAD_BATCHNUM);
		return r;
	}

	batch = block->batch[num];
	/* This could happen easily: we might be asking for it
	 * ourselves, right now. */
	if (!batch || !batch_full(block, batch)) {
		log_debug(peer->log,
			  "We don't know batch %u of ", num);
		log_add_struct(peer->log, struct protocol_double_sha,
			       &req->block);
		r->error = cpu_to_le32(PROTOCOL_ERROR_UNKNOWN_BATCH);
		return r;
	}

	/* Now append transactions. */
	for (i = 0; i < batch->count; i++)
		tal_packet_append_trans(&r, batch->t[i]);
	r->num = cpu_to_le32(batch->count);
	r->error = cpu_to_le32(PROTOCOL_ERROR_NONE);

	assert(!peer->response);
	peer->response = r;

	log_debug(peer->log, "Sending PROTOCOL_RESP_BATCH for %u of ", num);
	log_add_struct(peer->log, struct protocol_double_sha, &req->block);
	
	return NULL;
}

static enum protocol_error
unmarshall_batch(struct log *log,
		 const struct block *block,
		 size_t batchnum,
		 struct transaction_batch *batch,
		 const struct protocol_resp_batch *resp)
{
	size_t max = batch_max(block, batchnum);
	size_t size;
	const char *buffer;

	batch->trans_start = batchnum << PETTYCOIN_BATCH_ORDER;

	/* We must agree on number (and you must send whole batch!). */
	if (le32_to_cpu(resp->num) != max) {
		log_unusual(log, "Peer returned %u not %zu for batch %zu of ",
			    le32_to_cpu(resp->num), max, batchnum);
		log_add_struct(log, struct protocol_double_sha, &block->sha);
		return PROTOCOL_ERROR_DISAGREE_BATCHSIZE;
	}

	buffer = (char *)(resp + 1);
	size = le32_to_cpu(resp->len) - sizeof(*resp);

	for (batch->count = 0; batch->count < max; batch->count++) {
		size_t used;
		enum protocol_error err;

		batch->t[batch->count] = (union protocol_transaction *)buffer;
		err = unmarshall_transaction(buffer, size, &used);
		if (err) {
			log_unusual(log, "Peer resp_batch transaction %u/%zu"
				    " for len %zu/%u gave error ",
				    batch->count, max,
				    le32_to_cpu(resp->len) - size,
				    le32_to_cpu(resp->len));
			log_add_enum(log, enum protocol_error, err);
			return err;
		}
		size -= used;
		buffer += used;
	}

	if (size) {
		log_unusual(log, "Peer resp_batch leftover %zu bytes of %u",
			    size, le32_to_cpu(resp->len));
		return PROTOCOL_INVALID_LEN;
	}

	return PROTOCOL_ERROR_NONE;
}

static struct protocol_req_err *
receive_batch_resp(struct peer *peer, struct protocol_resp_batch *resp)
{
	struct block *block = peer->batch_requested_block;
	u32 batchnum = peer->batch_requested_num;
	enum protocol_error err;
	struct transaction_batch *batch;
	unsigned int bad_transnum, bad_input, bad_transnum2;
	union protocol_transaction *bad_intrans;

	if (le32_to_cpu(resp->len) < sizeof(*resp)) {
		log_unusual(peer->log,
			    "Peer sent PROTOCOL_RESP_BATCH with bad length %u",
			    le32_to_cpu(resp->len));
		return protocol_req_err(peer, PROTOCOL_INVALID_LEN);
	}

	switch (le32_to_cpu(resp->error)) {
	case PROTOCOL_ERROR_NONE:
		break;

	case PROTOCOL_ERROR_UNKNOWN_BLOCK:
		log_unusual(peer->log, "Peer does not know block for batch ");
		log_add_struct(peer->log, struct protocol_double_sha,
			       &block->sha);
		return NULL;

	case PROTOCOL_ERROR_BAD_BATCHNUM:
		log_unusual(peer->log, "Peer does not like batch number %u for ",
			    batchnum);
		log_add_struct(peer->log, struct protocol_double_sha,
			       &block->sha);
		return protocol_req_err(peer, PROTOCOL_ERROR_DISAGREE_BATCHNUM);

	case PROTOCOL_ERROR_UNKNOWN_BATCH:
		/* FIXME: well, don't keep asking then! */
		log_debug(peer->log, "Peer does not know batch ");
		log_add_struct(peer->log, struct protocol_double_sha, &block->sha);
		return NULL;

	default:
		log_unusual(peer->log, "Peer returned %u for batch %u of ",
			    le32_to_cpu(resp->error), peer->batch_requested_num);
		log_add_struct(peer->log, struct protocol_double_sha,
			       &block->sha);
		return protocol_req_err(peer, PROTOCOL_INVALID_RESPONSE);
	}

	/* Attach to response so we get freed with it on failure. */
	batch = talz(resp, struct transaction_batch);

	/* Unmarshall batch. */
	err = unmarshall_batch(peer->log, block, peer->batch_requested_num,
			       batch, resp);
	if (err)
		return protocol_req_err(peer, err);

	/* Peer should know better than to send invalid batch! */
	if (!batch_belongs_in_block(block, batch))
		return protocol_req_err(peer, PROTOCOL_INVALID_RESPONSE);

	err = batch_validate_transactions(peer->state, peer->log,
					  peer->batch_requested_block, batch,
					  &bad_transnum, &bad_input,
					  &bad_intrans);
	if (err) {
		/* We tell *everyone* about bad block, not just this peer. */
		invalidate_block_badtrans(peer->state, block, err,
					  bad_transnum, bad_input,
					  bad_intrans);
		return NULL;
	}

	if (!check_batch_order(peer->state, peer->batch_requested_block,
			       batch, &bad_transnum, &bad_transnum2)) {
		log_unusual(peer->log, "Peer gave invalid batch %u for ",
			    batchnum);
		log_add_struct(peer->log, struct protocol_double_sha,
			       &block->sha);
		log_add(peer->log, " %u vs %u", bad_transnum, bad_transnum2);
		/* We tell *everyone* about bad block, not just this peer. */
		invalidate_block_misorder(peer->state, block,
					  bad_transnum, bad_transnum2);
		return NULL;
	}

	/* block will now own batch */
	put_batch_in_block(peer->state, block, batch);

	/* batch now owns the packet */
	tal_steal(batch, resp);

	log_debug(peer->log, "Added batch %u to ", batchnum);
	log_add_struct(peer->log, struct protocol_double_sha,
			       &block->sha);

	/* FIXME: If not on generating chain, steal transactions for pending */

	/* FIXME: only do this if we gained something. */
	restart_generating(peer->state);
	return NULL;
}

/* Packet arrives. */
static struct io_plan pkt_in(struct io_conn *conn, struct peer *peer)
{
	const struct protocol_net_hdr *hdr = peer->incoming;
	tal_t *ctx = tal_arr(peer, char, 0);
	struct block *mutual;
	u32 len, type;

	len = le32_to_cpu(hdr->len);
	type = le32_to_cpu(hdr->type);

	log_debug(peer->log, "Received ");
	log_add_enum(peer->log, enum protocol_req_type, type);

	/* Recipient function should steal this if it should outlive function. */
	tal_steal(ctx, peer->incoming);

	/* Requests must be one-at-a-time. */
	if (type < PROTOCOL_REQ_MAX  && peer->curr_in_req != PROTOCOL_REQ_NONE) {
		log_unusual(peer->log,
			    "Peer placed request %u while %u still pending",
			    type, peer->curr_in_req);
		return io_close();
	}

	switch (type) {
	case PROTOCOL_REQ_NEW_BLOCK:
		log_debug(peer->log, "Received PROTOCOL_REQ_NEW_BLOCK");
		if (peer->curr_in_req != PROTOCOL_REQ_NONE)
			goto unexpected_req;
		peer->curr_in_req = PROTOCOL_REQ_NEW_BLOCK;
		peer->error_pkt = receive_block(peer, peer->incoming);
		if (peer->error_pkt)
			goto send_error;
			
		break;

	case PROTOCOL_RESP_NEW_BLOCK: {
		struct protocol_resp_new_block *resp = (void *)hdr;
		log_debug(peer->log, "Received PROTOCOL_RESP_NEW_BLOCK");
		if (len != sizeof(*resp))
			goto bad_resp_length;
		/* FIXME: formalize this check & reset req pattern! */
		if (peer->curr_out_req != PROTOCOL_REQ_NEW_BLOCK)
			goto unexpected_resp;

		/* If we know the block they know, update it. */
		mutual = block_find_any(peer->state, &resp->final);
		if (mutual)
			update_mutual(peer, mutual);
			
		peer->curr_out_req = PROTOCOL_REQ_NONE;
		break;
	}

	case PROTOCOL_REQ_NEW_TRANSACTION:
		log_debug(peer->log,
			  "Received PROTOCOL_REQ_NEW_TRANSACTION");
		if (peer->curr_in_req != PROTOCOL_REQ_NONE)
			goto unexpected_req;
		peer->curr_in_req = PROTOCOL_REQ_NEW_TRANSACTION;
		peer->error_pkt = receive_trans(peer, peer->incoming);
		if (peer->error_pkt)
			goto send_error;
		break;

	case PROTOCOL_RESP_NEW_TRANSACTION: {
		struct protocol_resp_new_transaction *resp = (void *)hdr;
		log_debug(peer->log, "Received PROTOCOL_RESP_NEW_TRANSACTION");
		if (len != sizeof(*resp))
			goto bad_resp_length;
		if (peer->curr_out_req != PROTOCOL_REQ_NEW_TRANSACTION)
			goto unexpected_resp;

		if (le32_to_cpu(resp->error) != PROTOCOL_ERROR_NONE) {
			log_debug(peer->log,
				  "Error %u on PROTOCOL_RESP_NEW_TRANSACTION ",
				  le32_to_cpu(resp->error));
			log_add_struct(peer->log, union protocol_transaction,
				       peer->new_trans_pending->t);
		}
		tal_free(peer->new_trans_pending);
		peer->curr_out_req = PROTOCOL_REQ_NONE;
		break;
	}

	case PROTOCOL_REQ_BATCH:
		log_debug(peer->log,
			  "Received PROTOCOL_REQ_BATCH");
		if (peer->curr_in_req != PROTOCOL_REQ_NONE)
			goto unexpected_req;
		peer->curr_in_req = PROTOCOL_REQ_BATCH;
		peer->error_pkt = receive_batch_req(peer, peer->incoming);
		if (peer->error_pkt)
			goto send_error;
		break;

	case PROTOCOL_RESP_BATCH:
		log_debug(peer->log,
			  "Received PROTOCOL_RESP_BATCH");
		if (peer->curr_out_req != PROTOCOL_REQ_BATCH)
			goto unexpected_resp;
		peer->error_pkt = receive_batch_resp(peer, peer->incoming);
		if (peer->error_pkt)
			goto send_error;
		peer->curr_out_req = PROTOCOL_REQ_NONE;
		break;
		
	case PROTOCOL_REQ_ERR:
		log_unusual(peer->log, "Received PROTOCOL_REQ_ERR %u",
			    cpu_to_le32(((struct protocol_req_err*)hdr)->error));
		return io_close();

	case PROTOCOL_RESP_ERR:
		log_unusual(peer->log, "Received PROTOCOL_RESP_ERR %u",
			    cpu_to_le32(((struct protocol_resp_err *)hdr)
					->error));
		return io_close();

	default:
		log_unusual(peer->log, "Unexpected packet %u", type);
		if (type >= PROTOCOL_RESP_NONE)
			return io_close();

		peer->error_pkt = protocol_resp_err(peer,
						    PROTOCOL_UNKNOWN_COMMAND);
	}

	/* Wake output if necessary. */
	io_wake(peer);

	tal_free(ctx);
	return io_read_packet(&peer->incoming, pkt_in, peer);

unexpected_req:
	log_unusual(peer->log, "Peer sent req %u after unacknowledged %u",
		    type, peer->curr_in_req);
	peer->error_pkt = protocol_resp_err(peer, PROTOCOL_SHOULD_BE_WAITING);
	goto send_error;

unexpected_resp:
	log_unusual(peer->log, "Peer responded with %u after we sent %u",
		    type, peer->curr_out_req);
	peer->error_pkt = protocol_req_err(peer, PROTOCOL_INVALID_RESPONSE);
	goto send_error;

bad_resp_length:
	log_unusual(peer->log, "Peer sent %u with bad length %u", type, len);
	peer->error_pkt = protocol_req_err(peer, PROTOCOL_INVALID_LEN);
	goto send_error;

send_error:
	/* In case writer is waiting. */
	io_wake(peer);

	/* Wait for writer to send error. */
	tal_free(ctx);
	return io_wait(peer, io_close_cb, NULL);
}

static void close_writer(struct io_conn *conn, struct peer *peer)
{
	assert(peer->w == conn);
	peer->w = NULL;
	if (peer->r)
		io_close_other(peer->r);
}

static void close_reader(struct io_conn *conn, struct peer *peer)
{
	assert(peer->r == conn);
	peer->r = NULL;
	if (peer->w)
		io_close_other(peer->w);
}

static struct io_plan check_welcome_ack(struct io_conn *conn,
					struct peer *peer)
{
	struct protocol_resp_err *wresp = peer->incoming;
	void *errpkt;

	assert(conn == peer->w);

	if (wresp->len != cpu_to_le32(sizeof(*wresp))) {
		log_unusual(peer->log, "Bad welcome ack len %u",
			    le32_to_cpu(wresp->len));
		errpkt = protocol_req_err(peer, PROTOCOL_INVALID_LEN);
		goto fail;
	}

	if (wresp->type != cpu_to_le32(PROTOCOL_RESP_ERR)) {
		log_unusual(peer->log, "Peer responded to welcome with %u",
			    le32_to_cpu(wresp->type));
		errpkt = protocol_req_err(peer, PROTOCOL_UNKNOWN_COMMAND);
		goto fail;
	}

	/* It doesn't like us. */
	if (wresp->error != cpu_to_le32(PROTOCOL_ERROR_NONE)) {
		log_unusual(peer->log, "Peer responded to welcome with error %u",
			    le32_to_cpu(wresp->error));
		peer_cache_del(peer->state, &peer->you, true);
		return io_close();
	}

	/* Where do we disagree on chain? */
	log_debug(peer->log, "Peer sent %u blocks",
		  le32_to_cpu(peer->welcome->num_blocks));
	peer->mutual = mutual_block_search(peer, peer->welcome->block,
					   le32_to_cpu(peer->welcome->num_blocks));
	/* We checked the genesis block in check_welcome! */
	assert(peer->mutual);

	log_info(peer->log, "Peer has mutual block %u", peer->mutual->blocknum);

	/* Time to go duplex on this connection. */
	peer->r = io_duplex(peer->w,
			    io_read_packet(&peer->incoming, pkt_in, peer));

	/* If one dies, kill both, and don't free peer when w freed! */
	io_set_finish(peer->r, close_reader, peer);
	io_set_finish(peer->w, close_writer, peer);
	tal_steal(peer->state, peer);

	return plan_output(conn, peer);

fail:
	return io_write_packet(peer, errpkt, io_close_cb); 
}

static struct io_plan receive_welcome_ack(struct io_conn *conn,
					  struct peer *peer)
{
	log_debug(peer->log, "Welcome ack sent: receiving theirs");
	return io_read_packet(&peer->incoming, check_welcome_ack, peer);
}

static struct io_plan welcome_received(struct io_conn *conn, struct peer *peer)
{
	struct protocol_resp_err *resp;
	struct state *state = peer->state;

	log_debug(peer->log, "Their welcome received");

	tal_steal(peer, peer->welcome);
	peer->state->num_peers_connected++;

	/* Are we talking to ourselves? */
	if (peer->welcome->random == state->random_welcome) {
		log_unusual(peer->log, "The peer is ourselves: closing");
		peer_cache_del(state, &peer->you, true);
		return io_close();
	}

	resp = protocol_resp_err(peer, check_welcome(state, peer->welcome));
	if (resp->error != cpu_to_le32(PROTOCOL_ERROR_NONE)) {
		log_unusual(peer->log, "Peer welcome was invalid (%u)",
			    le32_to_cpu(resp->error));
		return io_write_packet(peer, resp, io_close_cb);
	}

	log_info(peer->log, "Welcome received: listen port is %u",
		 be16_to_cpu(peer->welcome->listen_port));

	/* Replace port with see with port they want us to connect to. */
	peer->you.port = peer->welcome->listen_port;

	/* Create/update time for this peer. */
	peer_cache_update(state, &peer->you, time_to_sec(time_now()));

	return io_write_packet(peer, resp, receive_welcome_ack);
}

static struct io_plan welcome_sent(struct io_conn *conn, struct peer *peer)
{
	log_debug(peer->log, "Our welcome sent, awaiting theirs");
	return io_read_packet(&peer->welcome, welcome_received, peer);
}

static void destroy_peer(struct peer *peer)
{
	list_del_from(&peer->state->peers, &peer->list);
	if (peer->welcome) {
		peer->state->num_peers_connected--;
		log_info(peer->log, "Closing connected peer (%zu left)",
			 peer->state->num_peers_connected);
	} else {
		log_debug(peer->log, "Failed connect to peer %p", peer);
		/* Only delete from disk cache if we have *some* networking. */
		peer_cache_del(peer->state, &peer->you,
			       peer->state->num_peers_connected != 0);
	}

	peer->state->num_peers--;
	fill_peers(peer->state);
}

static struct io_plan setup_welcome(struct io_conn *unused, struct peer *peer)
{
	return io_write_packet(peer,
			       make_welcome(peer, peer->state, &peer->you),
			       welcome_sent);
}

void new_peer(struct state *state, int fd, const struct protocol_net_address *a)
{
	struct peer *peer = tal(state, struct peer);
	char name[INET6_ADDRSTRLEN + strlen(":65000:")];

	list_add(&state->peers, &peer->list);
	peer->state = state;
	peer->error_pkt = NULL;
	peer->welcome = NULL;
	peer->outgoing = NULL;
	peer->incoming = NULL;
	peer->response = NULL;
	peer->mutual = NULL;
	peer->curr_in_req = peer->curr_out_req = PROTOCOL_REQ_NONE;
	list_head_init(&peer->pending);
	list_head_init(&peer->complaints);

	/* If a, we need to connect to there. */
	if (a) {
		struct addrinfo *ai;

		peer->you = *a;

		log_debug(state->log, "Connecting to peer %p (%zu) at ",
			  peer, state->num_peers);
		log_add_struct(state->log, struct protocol_net_address,
			       &peer->you);

		ai = mk_addrinfo(peer, a);
		peer->w = io_new_conn(fd,
				      io_connect(fd, ai, setup_welcome, peer));
		tal_free(ai);
	} else {
		if (!get_fd_addr(fd, &peer->you)) {
			log_unusual(state->log,
				    "Could not get address for peer: %s",
				    strerror(errno));
			tal_free(peer);
			close(fd);
			return;
		}
		peer->w = io_new_conn(fd, setup_welcome(NULL, peer));
		log_debug(state->log, "Peer %p (%zu) connected from ",
			  peer, state->num_peers);
		log_add_struct(state->log, struct protocol_net_address,
			       &peer->you);
	}

	if (inet_ntop(AF_INET6, peer->you.addr, name, sizeof(name)) == NULL)
		strcpy(name, "UNCONVERTABLE-IPV6");
	sprintf(name + strlen(name), ":%u:", be16_to_cpu(peer->you.port));
	peer->log = new_log(peer, state->log,
			    name, state->log_level, PEER_LOG_MAX);

	state->num_peers++;
	tal_add_destructor(peer, destroy_peer);

	/* Conn owns us: we vanish when it does. */
	tal_steal(peer->w, peer);
}

static struct io_plan setup_peer(struct io_conn *conn, struct state *state)
{
	struct peer *peer = tal(conn, struct peer);

	peer->state = state;
	if (!get_fd_addr(io_conn_fd(conn), &peer->you)) {
		log_unusual(state->log, "Could not get address for peer: %s",
			    strerror(errno));
		return io_close();
	}

	log_info(state->log, "Set up --connect peer %zu at ", state->num_peers);
	log_add_struct(state->log, struct protocol_net_address, &peer->you);

	state->num_peers++;
	tal_add_destructor(peer, destroy_peer);

	return setup_welcome(conn, peer);
}

/* We use this for command line --connect. */
bool new_peer_by_addr(struct state *state, const char *node, const char *port)
{
	return dns_resolve_and_connect(state, node, port, setup_peer);
}
