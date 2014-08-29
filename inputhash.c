#include "hash_tx.h"
#include "inputhash.h"
#include "tx.h"
#include <ccan/hash/hash.h>
#include <ccan/structeq/structeq.h>

const struct inputhash_key *inputhash_keyof(const struct inputhash_elem *elem)
{
	return &elem->output;
}

size_t inputhash_hashfn(const struct inputhash_key *key)
{
	return hash_any(&key->tx, sizeof(key->tx), key->output_num);
}

bool inputhash_eq(const struct inputhash_elem *elem,
		  const struct inputhash_key *output)
{
	return output->output_num == elem->output.output_num
		&& structeq(&output->tx, &elem->output.tx);
}

static struct inputhash_elem *inputhash_i(struct htable *ht,
					  const struct inputhash_key *key,
					  struct inputhash_elem *te,
					  struct inputhash_iter *i,
					  size_t h)
{
	while (te) {
		if (inputhash_eq(te, key))
			break;
		te = htable_nextval(ht, &i->i, h);
	}
	return te;
}

struct inputhash_elem *inputhash_firstval(struct inputhash *inputhash,
					  const struct protocol_tx_id *tx,
					  u16 output_num,
					  struct inputhash_iter *i)
{
	struct inputhash_key key;
	size_t h;

	key.tx = *tx;
	key.output_num = output_num;
	h = inputhash_hashfn(&key);

	return inputhash_i(&inputhash->raw, &key,
			   htable_firstval(&inputhash->raw, &i->i, h),
			   i, h);
}

struct inputhash_elem *inputhash_nextval(struct inputhash *inputhash,
					 const struct protocol_tx_id *tx,
					 u16 output_num,
					 struct inputhash_iter *i)
{
	struct inputhash_key key;
	size_t h;

	key.tx = *tx;
	key.output_num = output_num;
	h = inputhash_hashfn(&key);

	return inputhash_i(&inputhash->raw, &key,
			   htable_nextval(&inputhash->raw, &i->i, h),
			   i, h);
}

void inputhash_add_tx(struct inputhash *inputhash,
		      const tal_t *ctx,
		      const union protocol_tx *tx)
{
	unsigned int i;

	for (i = 0; i < num_inputs(tx); i++) {
		struct inputhash_elem *ie;
		const struct protocol_input *inp = tx_input(tx, i);

		ie = tal(ctx, struct inputhash_elem);
		ie->output.tx = inp->input;
		ie->output.output_num = le16_to_cpu(inp->output);
		hash_tx(tx, &ie->used_by);

		inputhash_add(inputhash, ie);
	}
}

void inputhash_del_tx(struct inputhash *inputhash, const union protocol_tx *tx)
{
	unsigned int i;
	struct inputhash_elem *ie;
	struct inputhash_iter it;
	struct protocol_tx_id sha;

	hash_tx(tx, &sha);

	for (i = 0; i < num_inputs(tx); i++) {
		const struct protocol_input *inp = tx_input(tx, i);

		for (ie = inputhash_firstval(inputhash, &inp->input,
					     le16_to_cpu(inp->output), &it);
		     ie;
		     ie = inputhash_nextval(inputhash, &inp->input,
					    le16_to_cpu(inp->output), &it)) {
			if (structeq(&ie->used_by, &sha)) {
				htable_delval(&inputhash->raw, &it.i);
				tal_free(ie);
				break;
			}
		}
	}
}
