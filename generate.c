/* This helper tries to generate a block: stdin can add (verified)
 * transactions. */
#include <ccan/asort/asort.h>
#include <ccan/str/str.h>
#include <ccan/err/err.h>
#include <ccan/tal/tal.h>
#include <ccan/read_write_all/read_write_all.h>
#include <ccan/array_size/array_size.h>
#include <ccan/cast/cast.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/select.h>
#include <errno.h>
#include <time.h>
#include "version.h"
#include "features.h"
#include "protocol.h"
#include "merkle_transactions.h"
#include "shadouble.h"
#include "version.h"
#include "transaction_cmp.h"
#include "difficulty.h"
#include "marshall.h"
#include <assert.h>

static volatile bool input = true;

static void input_ready(int signum)
{
	input = true;
}

static bool valid_difficulty(u32 difficulty)
{
	u32 mantissa, exp;

	exp = difficulty >> 24;
	mantissa = difficulty & 0x00FFFFFF;

	if (exp < 3 || exp > SHA256_DIGEST_LENGTH)
		return false;
	if (!mantissa)
		return false;
	return true;
}

struct working_block {
	u32 feature_counts[8];
	struct protocol_block_header hdr;
	struct protocol_double_sha *merkles;
	u8 *prev_merkles;
	struct protocol_block_tailer tailer;
	union protocol_transaction **transactions;
	struct protocol_double_sha hash_of_merkles;
	struct protocol_double_sha hash_of_prev_merkles;

	/* Unfinished hash without tailer. */
	SHA256_CTX partial;
};

/* Update w->merkles, and w->hash_of_merkles */
static void merkle_hash_transactions(struct working_block *w)
{
	u32 i, num_trans, num_merk;
	SHA256_CTX ctx;

	num_trans = le32_to_cpu(w->hdr.num_transactions);
	num_merk = num_merkles(num_trans);

	if (tal_count(w->merkles) != num_merk << PETTYCOIN_BATCH_ORDER)
		tal_resize(&w->merkles, num_merk << PETTYCOIN_BATCH_ORDER);

	/* Create merkle hashes for each batch of transactions, and also
	 * hash together those merkles. */
	SHA256_Init(&ctx);
	
	for (i = 0; i < num_merk; i++) {
		merkle_transactions(NULL, 0,
				    w->transactions + (i<<PETTYCOIN_BATCH_ORDER),
				    (1 << PETTYCOIN_BATCH_ORDER),
				    &w->merkles[i]);
		SHA256_Update(&ctx, &w->merkles[i], sizeof(w->merkles[i]));
	}
	SHA256_Double_Final(&ctx, &w->hash_of_merkles);
}

static void update_partial_hash(struct working_block *w)
{
	SHA256_Init(&w->partial);
	SHA256_Update(&w->partial, &w->hash_of_prev_merkles,
		      sizeof(w->hash_of_prev_merkles));
	SHA256_Update(&w->partial, &w->hash_of_merkles,
		      sizeof(w->hash_of_merkles));
	SHA256_Update(&w->partial, &w->hdr, sizeof(w->hdr));
}

/* Create a new block. */
static struct working_block *
new_working_block(const tal_t *ctx,
		  u32 difficulty,
		  u8 *prev_merkles,
		  unsigned long num_prev_merkles,
		  const struct protocol_double_sha *prev_block,
		  const struct protocol_address *fees_to)
{
	struct working_block *w;
	SHA256_CTX shactx;

	w = tal(ctx, struct working_block);
	if (!w)
		return NULL;

	memset(w->feature_counts, 0, sizeof(w->feature_counts));

	w->transactions = tal_arr(w, union protocol_transaction *, 0);
	w->merkles = tal_arr(w, struct protocol_double_sha, num_merkles(0));
	if (!w->transactions || !w->merkles)
		return tal_free(w);

	w->hdr.version = current_version();
	w->hdr.features_vote = 0;
	memset(w->hdr.nonce2, 0, sizeof(w->hdr.nonce2));
	w->hdr.prev_block = *prev_block;
	w->hdr.num_transactions = cpu_to_le32(0);
	w->hdr.num_prev_merkles = cpu_to_le32(num_prev_merkles);
	w->hdr.fees_to = *fees_to;

	w->tailer.timestamp = cpu_to_le32(time(NULL));
	w->tailer.nonce1 = cpu_to_le32(0);
	w->tailer.difficulty = cpu_to_le32(difficulty);

	/* Hash prev_merkles: it doesn't change */
	w->prev_merkles = prev_merkles;
	SHA256_Init(&shactx);
	SHA256_Update(&shactx, w->prev_merkles, num_prev_merkles);
	SHA256_Double_Final(&shactx, &w->hash_of_prev_merkles);

	merkle_hash_transactions(w);
	update_partial_hash(w);
	return w;
}

/* Append a new transaction to the block. */
static bool add_transaction(struct working_block *w,
			    const union protocol_transaction *trans)
{
	unsigned int i;
	u8 new_features = 0;
	u32 num_trans, num_merk;

	num_trans = le32_to_cpu(w->hdr.num_transactions) + 1;

	/* Check for 2^32 transactions: discard if over. */
	if (num_trans == 0) {
		tal_free(trans);
		return true;
	}

	num_merk = num_merkles(num_trans);

	/* We always keep whole number of batches of transactions. */
	if (tal_count(w->transactions) != (num_merk << PETTYCOIN_BATCH_ORDER)) {
		/* FIXME: Assumes NULL == bitwise 0! */
		tal_resizez(&w->transactions,
			    num_merk << PETTYCOIN_BATCH_ORDER);
	}

	/* Append transaction. */
	w->transactions[num_trans - 1]
		= cast_const(union protocol_transaction *, trans);
	w->hdr.num_transactions = cpu_to_le32(num_trans);

	asort(w->transactions, num_trans, transaction_ptr_cmp, NULL);
	merkle_hash_transactions(w);

	/* Update features. */
	for (i = 0; i < ARRAY_SIZE(w->feature_counts); i++) {
		if (trans->hdr.features & (1 << i))
			w->feature_counts[i]++;
		/* If less than half vote for it, clear feature. */
		if (w->feature_counts[i] < num_trans / 2)
			new_features &= ~(1 << i);
	}
	w->hdr.features_vote = new_features;
	update_partial_hash(w);
	return true;
}

static void increment_nonce2(struct protocol_block_header *hdr)
{
	unsigned int i;

	for (i = 0; i < sizeof(hdr->nonce2); i++) {
		hdr->nonce2[i]++;
		if (hdr->nonce2[i])
			break;
	}
}

/* Try to solve the block. */
static bool solve_block(struct working_block *w)
{
	struct protocol_double_sha sha;
	SHA256_CTX ctx;
	uint32_t *nonce1;

	ctx = w->partial;
	SHA256_Update(&ctx, &w->tailer, sizeof(w->tailer));
	SHA256_Double_Final(&ctx, &sha);

	if (beats_target(&sha, le32_to_cpu(w->tailer.difficulty)))
		return true;

	/* Keep sparse happy: we don't care about nonce endianness. */
	nonce1 = (ENDIAN_CAST uint32_t *)&w->tailer.nonce1;

	/* Increment nonce1. */
	(*nonce1)++;

	/* And occasionally timestamp. */
	if ((*nonce1 & 0xFFFF) == 0) {
		w->tailer.timestamp = cpu_to_le32(time(NULL));

		/* If nonce1 completely wraps, time to update nonce2. */
		if (*nonce1 == 0) {
			increment_nonce2(&w->hdr);
			update_partial_hash(w);
		}
	}

	return false;
}

static bool read_all_or_none(int fd, void *buf, size_t len)
{
	size_t off = 0;

	while (off < len) {
		int r = read(STDIN_FILENO, (char *)buf + off, len - off);
		if (r == 0) {
			/* Terminated cleanly? */
			if (off == 0)
				return false;
			errx(1, "Short reading transaction");
		}
		if (r == -1) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				/* Nothing there?  OK. */
				if (off == 0)
					return false;
				/* May spin, but shouldn't be long. */
				continue;
			}
			err(1, "Reading transaction");
		}
		off += r;
	}
	return true;
}

/* Return false on EOF. */
static bool read_transaction(struct working_block *w)
{
	void *buf;
	u32 len;

	/* Gratuitous initial read handles race */
	if (!read_all_or_none(STDIN_FILENO, &len, sizeof(len)))
		return true;

	buf = tal_arr(w, char, len);
	if (!buf)
		err(1, "Allocating %u bytes", len);

	if (!read_all_or_none(STDIN_FILENO, buf, len))
		errx(1, "Short read reading transaction");

	if (!add_transaction(w, buf))
		err(1, "Adding transaction");

	return true;
}

static bool char_to_hex(u8 *val, char c)
{
	if (c >= '0' && c <= '9') {
		*val = c - '0';
		return true;
	}
 	if (c >= 'a' && c <= 'f') {
		*val = c - 'a' + 10;
		return true;
	}
 	if (c >= 'A' && c <= 'F') {
		*val = c - 'A' + 10;
		return true;
	}
	return false;
}

static bool from_hex(const char *str, u8 *buf, size_t bufsize)
{
	u8 v1, v2;

	while (*str) {
		if (!char_to_hex(&v1, str[0]) || !char_to_hex(&v2, str[1]))
			return false;
		if (!bufsize)
			return false;
		*(buf++) = (v1 << 4) | v2;
		str += 2;
		bufsize--;
	}
	return bufsize == 0;
}

/* 32 bit length, then block, then the transactions included. */
static void write_block(int fd, const struct working_block *w)
{
	u32 len, i;
	void *buf;

	buf = marshall_block(w, &w->hdr, w->merkles, w->prev_merkles,
			       &w->tailer, &len);

	write_all(fd, &len, sizeof(len));
	write_all(fd, buf, len);

	/* Now write out the transactions, in order. */
	for (i = 0; i < le32_to_cpu(w->hdr.num_transactions); i++) {
		len = marshall_transaction_len(w->transactions[i]);
		/* Must be valid transaction, since daemon sent it to us! */
		assert(len);
		write_all(fd, &len, sizeof(len));
		write_all(fd, w->transactions[i], len);
	}
}

int main(int argc, char *argv[])
{
	tal_t *ctx = tal(NULL, char);
	struct working_block *w;
	struct protocol_address reward_address;
	struct protocol_double_sha prev_hash;
	u8 *prev_merkles;
	u32 difficulty, num_prev_merkles;

	err_set_progname(argv[0]);

	if (argc != 5 && argc != 6)
		errx(1, "Usage: %s <reward_addr> <difficulty> <prevhash>"
		     " <num-prev-merkles> [<nonce>]",
			argv[0]);

	if (!from_hex(argv[1], reward_address.addr, sizeof(reward_address)))
		errx(1, "Invalid reward address");

	difficulty = strtoul(argv[2], NULL, 0);
	if (!valid_difficulty(difficulty))
		errx(1, "Invalid difficulty");

	if (!from_hex(argv[3], prev_hash.sha, sizeof(prev_hash)))
		errx(1, "Invalid previous hash");

	num_prev_merkles = strtoul(argv[4], NULL, 0);
	prev_merkles = tal_arr(ctx, u8, num_prev_merkles);

	/* Read in prev merkles */
	if (!read_all(STDIN_FILENO, prev_merkles, num_prev_merkles))
		err(1, "Reading %u previous merkles from stdin",
		    num_prev_merkles);

	w = new_working_block(ctx, difficulty, prev_merkles, num_prev_merkles,
			      &prev_hash, &reward_address);

	if (argv[5]) {
		strncpy((char *)w->hdr.nonce2, argv[5],
			sizeof(w->hdr.nonce2));
		update_partial_hash(w);
	}

	signal(SIGIO, input_ready);
	if (fcntl(STDIN_FILENO, F_SETOWN, getpid()) != 0)
		err(1, "Setting F_SETOWN on stdin");
	if (fcntl(STDIN_FILENO, F_SETFL,
		  fcntl(STDIN_FILENO, F_GETFL)|O_ASYNC|O_NONBLOCK) != 0)
		err(1, "Setting O_ASYNC and O_NONBLOCK on stdin");

	do {
		if (input) {
			input = false;
			if (!read_transaction(w)) {
				tal_free(ctx);
				return 0;
			}
		}
	} while (!solve_block(w));

	write_block(STDOUT_FILENO, w);

	tal_free(ctx);
	return 0;
}
