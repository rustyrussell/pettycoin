/* FIXME: Exclude genesis from difficulty check, so we can base on a
 * bitcoin block and be done. */
/* This calculates the genesis block values.  Supply 8 bytes of nonce:
 *
 * ./genesis 4 0x1dffffff "NYT Head"
 */
#include "hash_block.h"
#include "marshal.h"
#include "protocol.h"
#include "shadouble.h"
#include <assert.h>
#include <ccan/array_size/array_size.h>
#include <ccan/err/err.h>
#include <ccan/read_write_all/read_write_all.h>
#include <ccan/str/str.h>
#include <ccan/tal/tal.h>
#include <signal.h>
#include <stdio.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

struct worker {
	int txs_to_worker;
	int result_from_worker;
	pid_t child;
};

static void destroy_worker(struct worker *w)
{
	kill(w->child, SIGTERM);
	close(w->txs_to_worker);
	close(w->result_from_worker);
	waitpid(w->child, NULL, 0);
}

static const struct protocol_block_header *
solve(const tal_t *ctx,
      unsigned int threads,
      const char *difficulty,
      char *nonce,
      const u8 **shard_nums,
      const struct protocol_double_sha **merkles,
      const struct protocol_block_tailer **tailer)
{
	unsigned int i, maxfd = 0;
	fd_set set;
	tal_t *children = tal(ctx, char);
	struct protocol_pkt_block *ret;
	const u8 *prev_merkles;
	const struct protocol_block_header *hdr;
	char shard_order[STR_MAX_CHARS(u8)];

	sprintf(shard_order, "%u", PROTOCOL_INITIAL_SHARD_ORDER);

	FD_ZERO(&set);

	for (i = 0; i < threads; i++) {
		struct worker *w = tal(children, struct worker);
		int outfd[2], infd[2];

		/* Set each child on a difference nonce. */
		nonce[sizeof(hdr->nonce2)-1] += i % 96;
		nonce[sizeof(hdr->nonce2)-2] += (i / 96) % 96;
		assert(i < 96 * 96);

		/* Create worker process. */
		if (pipe(outfd) || pipe(infd)) {
			tal_free(ctx);
			err(1, "Creating pipes");
		}

		w->child = fork();
		if (w->child == (pid_t)-1) {
			tal_free(ctx);
			err(1, "fork");
		}
		if (w->child == 0) {
			close(outfd[0]);
			close(infd[1]);
			dup2(outfd[1], STDOUT_FILENO);
			dup2(infd[0], STDIN_FILENO);
			execl("./generate",
			      "generate",
			      /* Invalid reward address. */
			      "0000000000000000000000000000000000000000",
			      /* Difficult from cmdline. */
			      difficulty,
			      /* No previous block. */
			      "00000000000000000000000000000000"
			      "00000000000000000000000000000000",
			      /* No prev merkles. */
			      "0",
			      /* Genesis block is 0 depth. */
			      "0",
			      shard_order,
			      nonce, NULL);
			exit(127);
		}
		close(outfd[1]);
		close(infd[0]);
		/* Write "go" byte. */
		write(infd[1], "", 1);
		w->txs_to_worker = infd[1];
		w->result_from_worker = outfd[0];
		tal_add_destructor(w, destroy_worker);
		FD_SET(w->result_from_worker, &set);
		if (w->result_from_worker > maxfd)
			maxfd = w->result_from_worker;
	}

	select(maxfd+1, &set, NULL, NULL, NULL);
	for (i = 0; i < maxfd+1; i++) {
		if (FD_ISSET(i, &set)) {
			struct protocol_pkt_block hdr;

			if (read(i, &hdr, sizeof(hdr)) != sizeof(hdr)) {
				tal_free(ctx);
				err(1, "reading from child");
			}
			ret = (void *)tal_arr(ctx, char, le32_to_cpu(hdr.len));
			*ret = hdr;
			if (!read_all(i, ret + 1,
				      le32_to_cpu(hdr.len) - sizeof(hdr))) {
				tal_free(ctx);
				err(1, "reading transaction from child");
			}
			break;
		}
	}

	/* Kill off children. */
	tal_free(children);

	/* prev_merkles will be empty. */
	unmarshal_block(NULL, ret,
			&hdr, shard_nums, merkles, &prev_merkles, tailer);

	return hdr;
}

static void dump_array(const u8 *arr, size_t len)
{
	size_t i;

	printf("{ ");
	for (i = 0; i < len; i++)
		printf("0x%02x%s ", arr[i], i == len - 1 ? "" : ",");
	printf(" }");
}	

int main(int argc, char *argv[])
{
	unsigned int threads;
	tal_t *ctx = tal(NULL, char);
	const struct protocol_block_header *hdr;
	const struct protocol_block_tailer *tailer;
	const struct protocol_double_sha *merkles;
	struct protocol_double_sha sha;
	const u8 *shard_nums;
	unsigned int i;
	char nonce[sizeof(hdr->nonce2) + 1];

	err_set_progname(argv[0]);

	if (argc != 4)
		errx(1, "Usage: ./genesis threads difficulty nonce");

	threads = strtol(argv[1], NULL, 0);

	/* Copy nonce from commandline. */
	memset(nonce, ' ', sizeof(nonce)-1);
	if (strlen(argv[3]) > sizeof(hdr->nonce2))
		errx(1, "Nonce cannot be more than %zu bytes",
		     sizeof(hdr->nonce2));
	memcpy(nonce, argv[3], strlen(argv[3]));
	nonce[sizeof(nonce)-1] = '\0';

	hdr = solve(ctx, threads, argv[2], nonce, &shard_nums, &merkles,
		    &tailer);

	printf("#include \"genesis.h\"\n");
	printf("#include \"protocol.h\"\n\n");
	printf("static struct protocol_block_header genesis_hdr = {\n");
	printf("\t.version = %u,\n", hdr->version);
	printf("\t.features_vote = %u,\n", hdr->features_vote);
	printf("\t.shard_order = %u,\n", hdr->shard_order);
	{
		printf("\t.nonce2 = ");
		dump_array(hdr->nonce2, sizeof(hdr->nonce2));
		printf(",\n");
	}
	{
		printf("\t.fees_to = { ");
		dump_array(hdr->fees_to.addr, ARRAY_SIZE(hdr->fees_to.addr));
		printf(" }\n");
	}
	printf("};\n");

	printf("static const struct protocol_block_tailer genesis_tlr = {\n");
	printf("\t.timestamp = CPU_TO_LE32(%u),\n",
	       le32_to_cpu(tailer->timestamp));
	printf("\t.difficulty = CPU_TO_LE32(0x%08x),\n",
	       le32_to_cpu(tailer->difficulty));
	printf("\t.nonce1 = CPU_TO_LE32(%u)\n", le32_to_cpu(tailer->nonce1));
	printf("};\n");

	/* This will be all zeroes, but let's be precise. */
	printf("static const u8 genesis_shardnums[] = {\n");
	for (i = 0; i < (1U << hdr->shard_order); i++)
		printf("%s%u", i == 0 ? "" : ", ", shard_nums[i]);
	printf("\n};\n");

	printf("static const struct protocol_double_sha genesis_merkles[] = {\n");
	for (i = 0; i < (1U << hdr->shard_order); i++) {
		printf("{ ");
		dump_array(merkles[i].sha, ARRAY_SIZE(merkles[i].sha));
		printf("} ,\n");
	}
	printf("};\n");

	for (i = 0; i < (1U << hdr->shard_order); i++) {
		printf("static struct block_shard genesis_shard%i = {\n",
		       i);
		printf("\t.shardnum = %i\n", i);
		/* Rest all zeroes/NULLs. */
		printf("};\n");
	}
	printf("static struct block_shard *genesis_shards[] = {\n");
	for (i = 0; i < (1U << hdr->shard_order); i++)
		printf("%s&genesis_shard%i",
		       i == 0 ? "\t" : ", ", i);
	printf("\n};\n");

	hash_block(hdr, shard_nums, merkles, NULL, tailer, &sha);

	printf("struct block genesis = {\n"
	       "	.hdr = &genesis_hdr,\n"
	       "	.shard_nums = genesis_shardnums,\n"
	       "	.merkles = genesis_merkles,\n"
	       "	.tailer = &genesis_tlr,\n"
	       "	.shard = genesis_shards,\n"
	       "	.sha = { ");

	dump_array(sha.sha, ARRAY_SIZE(sha.sha));
	printf("}\n};\n");

	tal_free(ctx);
	return 0;
};
