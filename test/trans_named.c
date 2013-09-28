#include "helper_key.h"
#include "helper_gateway_key.h"
#include "../protocol.h"
#include "../hash_transaction.h"
#include "../create_transaction.h"
#include "../merkle_transactions.h"
#include "../shadouble.h"
#include "../block.h"
#include "../state.h"
#include "../prev_merkles.h"
#include "../version.h"
#include "../hash_block.h"
#include "../difficulty.h"
#include "../check_block.h"
#include <ccan/list/list.h>
#include <ccan/str/str.h>
#include <ccan/err/err.h>
#include <ccan/tal/tal.h>
#include <ccan/array_size/array_size.h>
#include <stdarg.h>
#include <stdlib.h>

static struct list_head helper_names = LIST_HEAD_INIT(helper_names);

struct named_trans {
	struct list_node list;
	const char *name;
	union protocol_transaction *t;
	u32 used;
	struct thash_elem *te;
};

static union protocol_transaction *find_name(const char *name,
					     u16 *output_num,
					     u32 *amount)
{
	size_t len = strcspn(name, "-");
	struct named_trans *i;

	list_for_each(&helper_names, i, list) {
		unsigned int num;
		u32 amt;

		if (memcmp(i->name, name, len) != 0)
			continue;
		if (i->name[len] != '\0')
			continue;
		if (streq(name + len, "")) {
			assert(i->t->hdr.type == TRANSACTION_NORMAL);
			num = 0;
			amt = le32_to_cpu(i->t->normal.send_amount);
		} else if (streq(name + len, "-change")) {
			assert(i->t->hdr.type == TRANSACTION_NORMAL);
			num = 1;
			amt = le32_to_cpu(i->t->normal.change_amount);
		} else {
			assert(i->t->hdr.type == TRANSACTION_FROM_GATEWAY);
			num = atoi(name + len + 1);
			assert(num < le16_to_cpu(i->t->gateway.num_outputs));
			amt = le32_to_cpu(i->t->gateway.output[num].send_amount);
		}
		if (i->used & (1 << num))
			errx(1, "Transaction %s already used", name);
		i->used |= (1 << num);
		if (output_num)
			*output_num = num;
		if (amount)
			*amount = amt;
		return i->t;
	}
	return NULL;
}

static struct named_trans *find_named_by_trans(union protocol_transaction *t)
{
	struct named_trans *i;

	list_for_each(&helper_names, i, list) {
		if (i->t == t)
			return i;
	}
	return NULL;
}

static void add_name(struct state *s,
		     const char *name, union protocol_transaction *t)
{
	struct named_trans *n = tal(s, struct named_trans);

	assert(!find_name(name, NULL, NULL));
	n->name = name;
	n->t = t;
	n->used = 0;
	n->te = NULL;
	list_add_tail(&helper_names, &n->list);
}

/* Named transactions: ouputs are called <name> and <name>-change. */
static union protocol_transaction *
named_trans(struct state *s, const char *tname,
	    unsigned int from_whom, unsigned int to_whom,
	    u32 amount, ...)
{
	va_list ap;
	const char *name;
	union protocol_transaction *t;
	struct protocol_input inputs[32];
	unsigned int i, total;

	va_start(ap, amount);
	i = total = 0;
	while ((name = va_arg(ap, const char *)) != NULL) {
		union protocol_transaction *input;
		u16 output;
		unsigned int amt;

		input = find_name(name, &output, &amt);
		if (!input)
			errx(1, "Could not find transaction %s", name);

		if (i >= ARRAY_SIZE(inputs))
			errx(1, "Too many inputs");
		hash_transaction(input, NULL, 0, &inputs[i].input);
		inputs[i].output = cpu_to_le16(output);
		total += amt;
		i++;
	}

	if (amount >= total)
		errx(1, "Amount %u vs total %u", amount, total);

	t = create_normal_transaction(s, helper_addr(to_whom),
				      amount, total - amount,
				      i, inputs,
				      helper_private_key(from_whom));
	add_name(s, tname, t);
	va_end(ap);

	return t;
}

/* -1 terminates to_whom list. */
static union protocol_transaction *
named_gateway(struct state *s, const char *tname, u32 amount, ...)
{
	va_list ap;
	union protocol_transaction *t;
	struct protocol_gateway_payment payments[32];
	unsigned int i;
	int to_whom;

	va_start(ap, amount);
	i = 0;
	while ((to_whom = va_arg(ap, int)) != -1) {
		if (i >= ARRAY_SIZE(payments))
			errx(1, "Too many payments");
		payments[i].send_amount = amount;
		payments[i].output_addr = *helper_addr(to_whom);
		i++;
	}

	t = create_gateway_transaction(s, helper_gateway_public_key(),
				       i, payments, helper_gateway_key());

	add_name(s, tname, t);
	va_end(ap);

	return t;
}

static struct protocol_double_sha *
merkle_hash_transactions(const tal_t *ctx,
			 union protocol_transaction *transactions[],
			 u32 num_trans)
{
	u32 i, num_merk;
	struct protocol_double_sha *ret;

	num_merk = num_merkles(num_trans);

	ret = tal_arr(ctx, struct protocol_double_sha, num_merk);

	/* Create merkle hashes for each batch of transactions. */
	for (i = 0; i < num_merk; i++) {
		merkle_transactions(NULL, 0,
				    transactions + (i<<PETTYCOIN_BATCH_ORDER),
				    (1 << PETTYCOIN_BATCH_ORDER),
				    &ret[i]);
	}

	return ret;
}


/* Solve a new block. 
 *
 * Assumptions: no difficulty change.
 * Fees go to helper_addr(0).
 * Time is 10 minutes after previous block.
 */
static struct block *block_with_names(struct state *s)
{
	struct protocol_block_header *hdr;
	struct protocol_double_sha *merkles;
	u8 *prev_merkles;
	struct protocol_block_tailer *tailer;
	struct block *block, *prev = list_tail(&s->blocks, struct block, list);
	struct named_trans *n;
	struct transaction_batch *batch;
	struct protocol_double_sha sha;
	unsigned int i;

	/* Create hashes for previous merkles. */
	prev_merkles = make_prev_merkles(s, s, prev, helper_addr(0));

	batch = talz(s, struct transaction_batch);
	batch->trans_start = 0;
	batch->count = 0;
	list_for_each(&helper_names, n, list) {
		if (n->te)
			continue;
		assert(batch->count < ARRAY_SIZE(batch->t));
		batch->t[batch->count++] = n->t;
	}

	asort(batch->t, batch->count, transaction_ptr_cmp, NULL);

	/* Create merkle hashes of the transactions. */
	merkles = merkle_hash_transactions(s, batch->t, batch->count);

	hdr = tal(s, struct protocol_block_header);
	hdr->version = current_version();
	hdr->features_vote = 0;
	memset(hdr->nonce2, 0, sizeof(hdr->nonce2));
	hdr->prev_block = prev->sha;
	hdr->num_transactions = cpu_to_le32(batch->count);
	hdr->num_prev_merkles = cpu_to_le32(tal_count(prev_merkles));
	hdr->fees_to = *helper_addr(0);

	tailer = tal(s, struct protocol_block_tailer);
	tailer->timestamp = cpu_to_le32(le32_to_cpu(prev->tailer->timestamp)
					+ 600);
	tailer->nonce1 = cpu_to_le32(0);
	tailer->difficulty = prev->tailer->difficulty;

	do {
		/* We assume we don't try more than 4 billion times. */
		tailer->nonce1 = cpu_to_le32(le32_to_cpu(tailer->nonce1)+1);
		hash_block(hdr, merkles, prev_merkles, tailer, &sha);
	} while (!beats_target(&sha, le32_to_cpu(tailer->difficulty)));

	block = check_block_header(s, hdr, merkles, prev_merkles, tailer);

	if (!put_batch_in_block(s, block, batch))
		abort();

	for (i = 0; i < batch->count; i++) {
		n = find_named_by_trans(batch->t[i]);

		n->te = tal(n, struct thash_elem);

		/* Add it to hash so we can find it in future. */
		hash_transaction(n->t, NULL, 0, &n->te->sha);
		n->te->block = block;
		n->te->tnum = i;
		thash_add(&s->thash, n->te);
	}

	return block;
}
