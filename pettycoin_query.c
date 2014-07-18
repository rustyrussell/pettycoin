/*
 * Helper to submit via JSON-RPC and get back response.
 */
#include <ccan/err/err.h>
#include <ccan/read_write_all/read_write_all.h>
#include <ccan/str/str.h>
#include <ccan/tal/str/str.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#define JSMN_STRICT 1
#define JSMN_PARENT_LINKS 1

# include "jsmn/jsmn.c"

#define NO_ERROR 0
#define ERROR_FROM_PETTYCOIN 1
#define ERROR_TALKING_TO_PETTYCOIN 2
#define ERROR_USAGE 3

/* Include " if it's a string. */
static const char *token_contents(const char *buffer,
				  const jsmntok_t *t)
{
	if (t->type == JSMN_STRING)
		return buffer + t->start - 1;
	return buffer + t->start;
}

/* Include " if it's a string. */
static int token_len(const jsmntok_t *t)
{
	if (t->type == JSMN_STRING)
		return t->end - t->start + 2;
	return t->end - t->start;
}

static bool tok_streq(const char *buffer, const jsmntok_t *tok,
		      const char *str)
{
	if (tok->type != JSMN_STRING)
		return false;
	return strncmp(buffer + tok->start, str, tok->end - tok->start) == 0;
}

static bool tok_is_null(const char *buffer, const jsmntok_t *tok)
{
	if (tok->type != JSMN_PRIMITIVE)
		return false;
	return buffer[tok->start] == 'n';
}

static const jsmntok_t *get_label(const char *buffer,
				  const jsmntok_t tok[],
				  size_t num_toks, const char *label)
{
	unsigned int i;

	for (i = 1; i < num_toks; i++) {
		if (tok[i].parent == 0 && tok_streq(buffer, &tok[i], label))
			return &tok[i];
		/* Another top-level object?  Stop. */
		if (tok[i].parent == -1)
			break;
	}
	return NULL;
}

static jsmntok_t *parse_input(const char *input, int len)
{
	jsmn_parser parser;
	jsmntok_t *toks;
	jsmnerr_t ret;

	toks = tal_arr(input, jsmntok_t, 10);

again:	
	jsmn_init(&parser);
	ret = jsmn_parse(&parser, input, len, toks, tal_count(toks));

	switch (ret) {
	case JSMN_ERROR_INVAL:
		errx(ERROR_TALKING_TO_PETTYCOIN,
		     "Malformed response '%.*s'", len, input);
	case JSMN_ERROR_PART:
		return tal_free(toks);
	case JSMN_ERROR_NOMEM:
		tal_resize(&toks, tal_count(toks) * 2);
		goto again;
	}

	/* Cut to length and return. */
	tal_resize(&toks, ret);
	return toks;
}

/* Simple test code to create a gateway transaction */
int main(int argc, char *argv[])
{
	int fd, i, off;
	const char *rpc_filename;
	char *cmd, *resp, *idstr;
	struct sockaddr_un addr;
	jsmntok_t *toks;
	const jsmntok_t *result, *error, *id;

	err_set_progname(argv[0]);

	if (argc < 3)
		errx(ERROR_USAGE,
		     "Usage: %s <rpcfile> <command> [<params>...]", argv[0]);

	rpc_filename = argv[1];

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (strlen(rpc_filename) + 1 > sizeof(addr.sun_path))
		errx(ERROR_USAGE, "rpc filename '%s' too long", rpc_filename);
	strcpy(addr.sun_path, rpc_filename);
	addr.sun_family = AF_UNIX;

	if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0)
		err(ERROR_TALKING_TO_PETTYCOIN,
		    "Connecting to '%s'", rpc_filename);

	idstr = tal_fmt(NULL, "pettycoin_query-%i", getpid());
	cmd = tal_fmt(idstr,
		      "{ \"method\" : \"%s\", \"id\" : \"%s\", \"params\" : [ ",
		      argv[2], idstr);

	for (i = 3; i < argc; i++) {
		/* Numbers are left unquoted, and quoted things left alone. */
		if (strspn(argv[i], "0123456789") == strlen(argv[i])
		    || argv[i][0] == '"')
			tal_append_fmt(&cmd, "%s", argv[i]);
		else
			tal_append_fmt(&cmd, "\"%s\"", argv[i]);
		if (i != argc - 1)
			tal_append_fmt(&cmd, ", ");
	}
	tal_append_fmt(&cmd, "] }");

	if (!write_all(fd, cmd, strlen(cmd)))
		err(ERROR_TALKING_TO_PETTYCOIN, "Writing command");

	resp = tal_arr(cmd, char, 100);
	off = 0;
	while ((i = read(fd, resp + off, tal_count(resp) - 1 - off)) > 0) {
		off += i;
		if (off == tal_count(resp) - 1)
			tal_resize(&resp, tal_count(resp) * 2);

		toks = parse_input(resp, off);
		if (toks)
			break;
	}
	resp[off] = '\0';

	result = get_label(resp, toks, tal_count(toks), "result");
	if (!result)
		errx(ERROR_TALKING_TO_PETTYCOIN,
		     "Missing 'result' in response '%s'", resp);
	error = get_label(resp, toks, tal_count(toks), "error");
	if (!error)
		errx(ERROR_TALKING_TO_PETTYCOIN,
		     "Missing 'error' in response '%s'", resp);
	id = get_label(resp, toks, tal_count(toks), "id");
	if (!id)
		errx(ERROR_TALKING_TO_PETTYCOIN,
		     "Missing 'id' in response '%s'", resp);
	if (!tok_streq(resp, id + 1, idstr))
		errx(ERROR_TALKING_TO_PETTYCOIN,
		     "Incorrect 'id' in response: %.*s",
		     token_len(id + 1), token_contents(resp, id + 1));

	if (tok_is_null(resp, error + 1)) {
		printf("%.*s\n",
		       token_len(result + 1), token_contents(resp, result + 1));
		tal_free(idstr);
		return 0;
	}

	printf("%.*s\n",
	       token_len(error + 1), token_contents(resp, error + 1));
	tal_free(idstr);
	return 1;
}
