#include "merkle_transactions.h"
#include "transaction.h"
#include "shadouble.h"
#include "hash_transaction.h"
#include "protocol.h"
#include <assert.h>
#include <string.h>
#include <ccan/tal/tal.h>

static void merkle_recurse(size_t off, size_t max_off, size_t num,
			   struct protocol_double_sha
			     (*fn)(size_t n, void *data),
			   void *data,
			   struct protocol_double_sha *merkle)
{
	/* Always a power of 2. */
	assert((num & (num-1)) == 0);
	assert(num != 0);

	if (num == 1) {
		if (off >= max_off)
			memset(merkle, 0, sizeof(*merkle));
		else
			*merkle = fn(off, data);
	} else {
		SHA256_CTX shactx;
		struct protocol_double_sha sub[2];

		num /= 2;
		merkle_recurse(off, max_off, num, fn, data, sub);
		merkle_recurse(off + num, max_off, num, fn, data, sub+1);
		
		SHA256_Init(&shactx);
		SHA256_Update(&shactx, sub, sizeof(sub));
		SHA256_Double_Final(&shactx, merkle);
	}
}

struct merkle_txinfo {
	const void *prefix;
	size_t prefix_len;
	const bitmap *txp_or_hash;
	const union txp_or_hash *u;
};

static struct protocol_double_sha merkle_tx(size_t n, void *data)
{
	struct merkle_txinfo *info = data;
	struct protocol_double_sha merkle;

	/* Already got hashes?  Just hash together. */
	if (bitmap_test_bit(info->txp_or_hash, n)) {
		SHA256_CTX shactx;
		const struct protocol_net_txrefhash *h;

		h = info->u[n].hash;

		SHA256_Init(&shactx);
		SHA256_Update(&shactx, &h->txhash, sizeof(h->txhash));
		SHA256_Update(&shactx, &h->refhash, sizeof(h->refhash));
		SHA256_Double_Final(&shactx, &merkle);
	} else {
		const union protocol_transaction *tx;
		const struct protocol_input_ref *refs;

		tx = info->u[n].txp.tx;
		refs = refs_for(info->u[n].txp);

		hash_tx_for_block(tx, info->prefix, info->prefix_len, refs,
				  num_inputs(tx), &merkle);
	}

	return merkle;
}

void merkle_transactions(const void *prefix, size_t prefix_len,
			 const bitmap *txp_or_hash,
			 const union txp_or_hash *u,
			 size_t off, size_t num_trans,
			 struct protocol_double_sha *merkle)
{
	struct merkle_txinfo txinfo;

	txinfo.prefix = prefix;
	txinfo.prefix_len = prefix_len;
	txinfo.txp_or_hash = txp_or_hash;
	txinfo.u = u;

	merkle_recurse(off, num_trans, 256, merkle_tx, &txinfo, merkle);
}

static struct protocol_double_sha merkle_hashes(size_t n, void *data)
{
	const struct protocol_double_sha **hashes = data;

	return *hashes[n];
}

void merkle_transaction_hashes(const struct protocol_double_sha **hashes,
			       size_t off, size_t num_hashes,
			       struct protocol_double_sha *merkle)
{
	merkle_recurse(off, num_hashes, 256, merkle_hashes, hashes, merkle);
}
