#include "block.h"
#include "chain.h"
#include "hex.h"
#include "json_add_tx.h"
#include "jsonrpc.h"
#include "state.h"
#include "txhash.h"
#include <ccan/tal/str/str.h>

static char *json_gettransaction(struct json_connection *jcon,
				 const jsmntok_t *params,
				 char **response)
{
	struct protocol_double_sha txhash;
	const jsmntok_t *txid;
	unsigned int confirms;
	struct txhash_elem *te;
	struct txhash_iter i;
	const union protocol_tx *tx;
	const struct block *block;

	json_get_params(jcon->buffer, params, "txid", &txid, NULL);
	if (!txid)
		return "Needs 'txid'";

	if (!from_hex(jcon->buffer + txid->start, txid->end - txid->start,
		      &txhash, sizeof(txhash))) {
		return tal_fmt(jcon, "txid %.*s not valid",
			       json_tok_len(txid),
			       json_tok_contents(jcon->buffer, txid));
	}

	te = txhash_firstval(&jcon->state->txhash, &txhash, &i);
	if (!te)
		return tal_fmt(jcon, "Unknown tx %.*s",
			       json_tok_len(txid),
			       json_tok_contents(jcon->buffer, txid));

	if (te->status == TX_PENDING) {
		confirms = 0;
		tx = te->u.tx;
		block = NULL;
	} else {
		tx = block_get_tx(te->u.block, te->shardnum, te->txoff);
		block = te->u.block;

		if (!block_preceeds(block, jcon->state->preferred_chain)) {
			/* FIXME: Report conflicts! */
			confirms = 0;
		} else {
			confirms = le32_to_cpu(jcon->state->preferred_chain->hdr->height)
				- le32_to_cpu(block->hdr->height);
		}
	}

	json_add_tx(response, NULL, jcon->state, tx, block, confirms);
	return NULL;
}

const struct json_command gettransaction_command = {
	"gettransaction", json_gettransaction,
	"Dump a transaction",
	"Takes <txid>"
};
