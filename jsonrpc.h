#ifndef PETTYCOIN_JSONRPC_H
#define PETTYCOIN_JSONRPC_H
#include "config.h"
#include <ccan/list/list.h>

struct json_connection {
	/* The global state */
	struct state *state;

	/* The buffer (required to interpret tokens). */
	char *buffer;

	/* Internal state: */
	/* How much is already filled. */
	size_t used;
	/* How much has just been filled. */
	size_t len_read;

	struct list_head output;
	const char *outbuf;
};

/* Add notification about something. */
void json_notify(struct json_connection *jcon, const char *result);

/* For initialization */
void setup_jsonrpc(struct state *state, const char *rpc_filename);

#endif /* PETTYCOIN_JSONRPC_H */
