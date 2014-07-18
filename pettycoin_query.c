/*
 * Helper to submit via JSON-RPC and get back response.
 */
#include "json.h"
#include <ccan/err/err.h>
#include <ccan/read_write_all/read_write_all.h>
#include <ccan/str/str.h>
#include <ccan/tal/str/str.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#define NO_ERROR 0
#define ERROR_FROM_PETTYCOIN 1
#define ERROR_TALKING_TO_PETTYCOIN 2
#define ERROR_USAGE 3

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
		bool valid;
		off += i;
		if (off == tal_count(resp) - 1)
			tal_resize(&resp, tal_count(resp) * 2);

		toks = json_parse_input(resp, off, &valid);
		if (toks)
			break;
		if (!valid)
			errx(ERROR_TALKING_TO_PETTYCOIN,
			     "Malformed response '%.*s'", off, resp);
	}
	resp[off] = '\0';

	result = json_get_label(resp, toks, "result");
	if (!result)
		errx(ERROR_TALKING_TO_PETTYCOIN,
		     "Missing 'result' in response '%s'", resp);
	error = json_get_label(resp, toks, "error");
	if (!error)
		errx(ERROR_TALKING_TO_PETTYCOIN,
		     "Missing 'error' in response '%s'", resp);
	id = json_get_label(resp, toks, "id");
	if (!id)
		errx(ERROR_TALKING_TO_PETTYCOIN,
		     "Missing 'id' in response '%s'", resp);
	if (!json_tok_streq(resp, id + 1, idstr))
		errx(ERROR_TALKING_TO_PETTYCOIN,
		     "Incorrect 'id' in response: %.*s",
		     json_tok_len(id + 1), json_tok_contents(resp, id + 1));

	if (json_tok_is_null(resp, error + 1)) {
		printf("%.*s\n",
		       json_tok_len(result + 1),
		       json_tok_contents(resp, result + 1));
		tal_free(idstr);
		return 0;
	}

	printf("%.*s\n",
	       json_tok_len(error + 1), json_tok_contents(resp, error + 1));
	tal_free(idstr);
	return 1;
}
