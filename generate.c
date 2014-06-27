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
#include "merkle_hashes.h"
#include "block.h"
#include "shadouble.h"
#include "version.h"
#include "tx_cmp.h"
#include "difficulty.h"
#include "marshal.h"
#include "generate.h"
#include "timestamp.h"
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
	u32 num_shards;
	u32 num_trans;
	struct protocol_block_header hdr;
	u8 *shard_nums;
	struct protocol_double_sha *merkles;
	u8 *prev_merkles;
	struct protocol_block_tailer tailer;
	struct protocol_double_sha ***trans_hashes;
	struct protocol_double_sha hash_of_merkles;
	struct protocol_double_sha hash_of_prev_merkles;

	/* Unfinished hash without tailer. */
	SHA256_CTX partial;
};

/* Update w->merkles[shard], and w->hash_of_merkles */
static void merkle_hash_shard(struct working_block *w, u32 shard)
{
	const struct protocol_double_sha **hashes;

	/* Introducing const here requires cast. */
	hashes = (const struct protocol_double_sha **)w->trans_hashes[shard];
	merkle_hashes(hashes, 0, w->shard_nums[shard], &w->merkles[shard]);
}

static void merkle_hash_changed(struct working_block *w)
{
	u32 i;
	SHA256_CTX ctx;

	/* Recalc hash of all merkles. */
	SHA256_Init(&ctx);
	for (i = 0; i < w->num_shards; i++)
		SHA256_Update(&ctx, &w->merkles[i], sizeof(w->merkles[i]));
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
	SHA256_Update(&w->partial, w->shard_nums,
		      sizeof(*w->shard_nums)*w->num_shards);
}

/* Create a new block. */
static struct working_block *
new_working_block(const tal_t *ctx,
		  u32 difficulty,
		  u8 *prev_merkles,
		  unsigned long num_prev_merkles,
		  u32 depth,
		  u8 shard_order,
		  const struct protocol_double_sha *prev_block,
		  const struct protocol_address *fees_to)
{
	struct working_block *w;
	SHA256_CTX shactx;
	u32 i;

	w = tal(ctx, struct working_block);
	if (!w)
		return NULL;

	memset(w->feature_counts, 0, sizeof(w->feature_counts));

	w->num_shards = 1 << shard_order;
	w->num_trans = 0;
	w->trans_hashes = tal_arr(w, struct protocol_double_sha **,
				  w->num_shards);
	w->shard_nums = tal_arrz(w, u8, w->num_shards);
	w->merkles = tal_arrz(w, struct protocol_double_sha, w->num_shards);
	if (!w->trans_hashes || !w->shard_nums || !w->merkles)
		return tal_free(w);
	for (i = 0; i < w->num_shards; i++) {
		w->trans_hashes[i] = tal_arr(w->trans_hashes,
					     struct protocol_double_sha *,
					     0);
		if (!w->trans_hashes[i])
			return tal_free(w);
	}

	w->hdr.version = current_version();
	w->hdr.features_vote = 0;
	memset(w->hdr.nonce2, 0, sizeof(w->hdr.nonce2));
	w->hdr.prev_block = *prev_block;
	w->hdr.shard_order = shard_order;
	w->hdr.num_prev_merkles = cpu_to_le32(num_prev_merkles);
	w->hdr.depth = cpu_to_le32(depth);
	w->hdr.fees_to = *fees_to;

	w->tailer.timestamp = cpu_to_le32(current_time());
	w->tailer.nonce1 = cpu_to_le32(0);
	w->tailer.difficulty = cpu_to_le32(difficulty);

	/* Hash prev_merkles: it doesn't change */
	w->prev_merkles = prev_merkles;
	SHA256_Init(&shactx);
	SHA256_Update(&shactx, w->prev_merkles, num_prev_merkles);
	SHA256_Double_Final(&shactx, &w->hash_of_prev_merkles);

	for (i = 0; i < w->num_shards; i++)
		merkle_hash_shard(w, i);
	merkle_hash_changed(w);

	update_partial_hash(w);
	return w;
}

/* Append a new transaction hash to the block. */
static bool add_tx(struct working_block *w, struct update *update)
{
	unsigned int i;
	u8 new_features = 0;
	size_t num;

	assert(update->shard < tal_count(w->shard_nums));
	assert(w->shard_nums[update->shard] < 255);
	assert(update->txoff <= w->shard_nums[update->shard]);

	num = w->shard_nums[update->shard];

	/* Assumes NULL == bitwise 0! */
	tal_resizez(&w->trans_hashes[update->shard], num + 1);

	/* Move later transactions. */
	memmove(w->trans_hashes[update->shard] + update->txoff + 1,
		w->trans_hashes[update->shard] + update->txoff,
		(num - update->txoff)
		* sizeof(w->trans_hashes[update->shard][0]));
	w->trans_hashes[update->shard][update->txoff] = &update->hash;
	w->shard_nums[update->shard]++;
	w->num_trans++;

	merkle_hash_shard(w, update->shard);
	merkle_hash_changed(w);

	for (i = 0; i < ARRAY_SIZE(w->feature_counts); i++) {
		if (update->features & (1 << i))
			w->feature_counts[i]++;
		/* If less than half vote for it, clear feature. */
		if (w->feature_counts[i] < w->num_trans / 2)
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

static void read_txs(struct working_block *w)
{
	struct update *update = tal(w, struct update);

	/* Gratuitous initial read handles race */
	while (read_all_or_none(STDIN_FILENO, update, sizeof(*update))) {
		if (!add_tx(w, update))
			err(1, "Adding transaction");
		update = tal(w, struct update);
	}

	tal_free(update);
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

/* 32 bit length, then block: caller knows transactions already. */
static void write_block(int fd, const struct working_block *w)
{
	struct protocol_pkt_block *b;
	u32 shard, i;

	b = marshal_block(w, &w->hdr, w->shard_nums, w->merkles,
			  w->prev_merkles, &w->tailer);
	if (!write_all(fd, b, le32_to_cpu(b->len)))
		err(1, "Writing out results: %s", strerror(errno));

	/* Write out the cookies. */
	for (shard = 0; shard < w->num_shards; shard++) {
		for (i = 0; i < w->shard_nums[shard]; i++) {
			/* cookie is just before hash */
			void **cookie = (void *)w->trans_hashes[shard][i];
			if (!write_all(fd, &cookie[-1], sizeof(void *)))
				err(1, "Writing out cookie: %s",
				    strerror(errno));
		}
	}
}

int main(int argc, char *argv[])
{
	tal_t *ctx = tal(NULL, char);
	struct working_block *w;
	struct protocol_address reward_address;
	struct protocol_double_sha prev_hash;
	u8 *prev_merkles;
	u32 difficulty, num_prev_merkles, depth, shard_order;

	err_set_progname(argv[0]);

	if (argc != 7 && argc != 8)
		errx(1, "Usage: %s <reward_addr> <difficulty> <prevhash>"
		     " <num-prev-merkles> <depth> <shardorder> [<nonce>]",
			argv[0]);

	if (!from_hex(argv[1], reward_address.addr, sizeof(reward_address)))
		errx(1, "Invalid reward address");

	difficulty = strtoul(argv[2], NULL, 0);
	if (!valid_difficulty(difficulty))
		errx(1, "Invalid difficulty");

	if (!from_hex(argv[3], prev_hash.sha, sizeof(prev_hash)))
		errx(1, "Invalid previous hash");

	depth = strtoul(argv[5], NULL, 0);
	shard_order = strtoul(argv[6], NULL, 0);
	num_prev_merkles = strtoul(argv[4], NULL, 0);
	prev_merkles = tal_arr(ctx, u8, num_prev_merkles + 1);

	/* Read in prev merkles, plus "go" byte.  If we are to
	 * terminate immediately, this might be 0 bytes. */
	if (!read_all_or_none(STDIN_FILENO, prev_merkles, num_prev_merkles + 1))
		exit(0);

	w = new_working_block(ctx, difficulty, prev_merkles, num_prev_merkles,
			      depth, shard_order, &prev_hash, &reward_address);

	if (argv[7]) {
		strncpy((char *)w->hdr.nonce2, argv[7],
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
			read_txs(w);
		}
	} while (!solve_block(w));

	write_block(STDOUT_FILENO, w);

	tal_free(ctx);
	return 0;
}
