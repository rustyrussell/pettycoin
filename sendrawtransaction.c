#include "check_tx.h"
#include "ecode_names.h"
#include "jsonrpc.h"
#include "marshal.h"
#include "peer.h"
#include "pending.h"
#include "todo.h"
#include "tx.h"
#include <ccan/tal/str/str.h>

static bool hexchar(char c, u8 *ret)
{
	if (c >= '0' && c <= '9') {
		*ret = c - '0';
		return true;
	}
	if (c >= 'a' && c <= 'f') {
		*ret = c - 'a' + 10;
		return true;
	}
	if (c >= 'A' && c <= 'F') {
		*ret = c - 'F' + 10;
		return true;
	}
	return false;
}

static void *dehex(const tal_t *ctx, const char *p, size_t len)
{
	u8 *ret = tal_arr(ctx, u8, len / 2), *out;

	out = ret;
	while (len) {
		u8 b1, b2;

		if (len == 1 || !hexchar(p[0], &b1) || !hexchar(p[1], &b2))
			return tal_free(ret);

		*out = (b1 << 4) | b2;
		out++;
		p += 2;
		len -= 2;
	}

	return ret;
}

static char *json_sendrawtransaction(struct json_connection *jcon,
				     const jsmntok_t *params,
				     char **response)
{
	union protocol_tx *tx;
	const jsmntok_t *tok;
	struct protocol_double_sha sha;
	enum protocol_ecode e;
	unsigned int bad_input_num;
	bool old;

	json_get_params(jcon->buffer, params, "tx", &tok, NULL);
	if (!tok)
		return "Need a tx parameter";

	tx = dehex(jcon, jcon->buffer + tok->start, tok->end - tok->start);
	if (!tx)
		return "Invalid hex string for tx";

	e = unmarshal_tx(tx, tal_count(tx), NULL);
	if (e != PROTOCOL_ECODE_NONE)
		return tal_fmt(jcon, "Error unmarshalling tx: %s",
			       ecode_name(e));

	e = check_tx(jcon->state, tx, NULL);
	if (e)
		return tal_fmt(jcon, "tx has an error: %s", ecode_name(e));

	hash_tx(tx, &sha);

	json_object_start(response, NULL);
	json_add_double_sha(response, "tx", &sha);

	switch (add_pending_tx(jcon->state, tx, &sha, &bad_input_num, &old)) {
	case ECODE_INPUT_OK:
		break;
	case ECODE_INPUT_UNKNOWN:
		/* Ask about this input. */
		todo_add_get_tx(jcon->state,
				&tx_input(tx, bad_input_num)->input);
		/* FIXME: we only report one unknown input! */
		json_object_start(response, "unknown_input");
		json_add_num(response, "input_num", bad_input_num);
		json_add_double_sha(response, "tx",
				    &tx_input(tx, bad_input_num)->input);
		json_object_end(response);
		/* It's still a success though. */
		break;
	case ECODE_INPUT_BAD:
		if (old)
			return tal_fmt(jcon,
				       "Input %u is too old", bad_input_num);
		return tal_fmt(jcon, "Input %u is invalid", bad_input_num);
	case ECODE_INPUT_BAD_AMOUNT:
		return tal_fmt(jcon, "Amount does not add up");
	case ECODE_INPUT_DOUBLESPEND:
		return tal_fmt(jcon, "Input %u already spent", bad_input_num);
	case ECODE_INPUT_CLAIM_BAD:
		return tal_fmt(jcon, "Claim is bad");
	}
	json_object_end(response);

	log_info(jcon->state->log, "JSON gave us TX ");
	log_add_struct(jcon->state->log, struct protocol_double_sha, &sha);

	/* Tell everyone. */
	send_tx_to_peers(jcon->state, NULL, tx);
	return NULL;
}

struct json_command sendrawtransaction_command = {
	"sendrawtransaction",
	json_sendrawtransaction,
	"Send a transaction to the network",
	"The transaction is a hex string."
};
