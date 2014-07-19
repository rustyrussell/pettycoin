/* Code for JSON_RPC API */
/* eg: { "method" : "echo", "params" : [ "hello", "Arabella!" ], "id" : "1" } */
#include "json.h"
#include "jsonrpc.h"
#include "log.h"
#include "state.h"
#include <ccan/array_size/array_size.h>
#include <ccan/err/err.h>
#include <ccan/io/io.h>
#include <ccan/read_write_all/read_write_all.h>
#include <ccan/tal/str/str.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>

struct json_buf {
	struct state *state;
	/* How much is already filled. */
	size_t used;
	/* How much has just been filled. */
	size_t len_read;
	char *buffer;

	/* Output (for freeing next time). */
	char *output;
};

static void free_buf(struct io_conn *conn, struct json_buf *buf)
{
	log_info(buf->state->log, "Closing json input (%s)", strerror(errno));
	tal_free(buf);
}

struct command {
	const char *name;
	char *(*dispatch)(const char *buffer,
			  const jsmntok_t *params,
			  char **response);
	const char *description;
};

static char *json_help(const char *buffer,
		       const jsmntok_t *params,
		       char **response);

static char *json_echo(const char *buffer,
		       const jsmntok_t *params,
		       char **response)
{
	tal_append_fmt(response, "{ \"num\" : %u, %.*s }",
		       params->size,
		       json_tok_len(params),
		       json_tok_contents(buffer, params));
	return NULL;
}

static const struct command cmdlist[] = {
	{ "help", json_help, "describe commands" },
	{ "echo", json_echo, "echo parameters" }
};

static char *json_help(const char *buffer,
		       const jsmntok_t *params,
		       char **response)
{
	unsigned int i;

	json_array_start(response);
	for (i = 0; i < ARRAY_SIZE(cmdlist); i++) {
		json_object(response,
			    "command", cmdlist[i].name, JSMN_STRING,
			    "description", cmdlist[i].description, JSMN_STRING,
			    NULL);
		json_array_next(response);
	}
	json_array_end(response);
	return NULL;
}

static const struct command *find_cmd(const char *buffer, const jsmntok_t *tok)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(cmdlist); i++)
		if (json_tok_streq(buffer, tok, cmdlist[i].name))
			return &cmdlist[i];
	return NULL;
}

/* Returns NULL if it's a fatal error. */
static char *parse_request(struct json_buf *buf, const jsmntok_t tok[])
{
	const jsmntok_t *method, *id, *params, *t;
	const struct command *cmd;
	char *result, *error;

	if (tok[0].type != JSMN_OBJECT) {
		log_unusual(buf->state->log, "Expected {} for json command");
		return NULL;
	}

	method = json_get_label(buf->buffer, tok, "method");
	params = json_get_label(buf->buffer, tok, "params");
	id = json_get_label(buf->buffer, tok, "id");

	if (!id || !method || !params) {
		log_unusual(buf->state->log, "json: No %s",
			    !id ? "id" : (!method ? "method" : "params"));
		return NULL;
	}

	id++;
	if (id->type != JSMN_STRING && id->type != JSMN_PRIMITIVE) {
		log_unusual(buf->state->log,
			    "Expected string/primitive for id");
		return NULL;
	}

	t = method + 1;
	if (t->type != JSMN_STRING) {
		log_unusual(buf->state->log, "Expected string for method");
		return NULL;
	}

	cmd = find_cmd(buf->buffer, t);
	if (!cmd) {
		return tal_fmt(buf,
			      "{ \"result\" : null,"
			      " \"error\" : \"Unknown command '%.*s'\","
			      " \"id\" : %.*s }\n",
			      (int)(t->end - t->start),
			      buf->buffer + t->start,
			      json_tok_len(id),
			      json_tok_contents(buf->buffer, id));
	}

	t = params + 1;
	if (t->type != JSMN_ARRAY) {
		log_unusual(buf->state->log, "Expected array after params");
		return NULL;
	}

	result = tal_arr(buf, char, 0);
	error = cmd->dispatch(buf->buffer, t, &result);
	if (error)
		return tal_fmt(buf,
			      "{ \"result\" : null,"
			      " \"error\" : \"%s\","
			      " \"id\" : %.*s }\n",
			      error,
			      json_tok_len(id),
			      json_tok_contents(buf->buffer, id));
	return tal_fmt(buf,
		       "{ \"result\" : %s,"
		       " \"error\" : null,"
		       " \"id\" : %.*s }\n",
		       result,
		       json_tok_len(id),
		       json_tok_contents(buf->buffer, id));
}

static struct io_plan read_json(struct io_conn *conn, struct json_buf *buf)
{
	jsmntok_t *toks;
	bool valid;

	buf->output = tal_free(buf->output);

	/* Resize larger if we're full. */
	buf->used += buf->len_read;
	if (buf->used == tal_count(buf->buffer))
		tal_resize(&buf->buffer, buf->used * 2);

	toks = json_parse_input(buf->buffer, buf->used, &valid);
	if (!toks) {
		if (!valid) {
			log_unusual(buf->state->log,
				    "Invalid token in json input: '%.*s'",
				    (int)buf->used, buf->buffer);
			return io_close();
		}
		/* We need more. */
		goto read_more;
	}

	/* Empty buffer? (eg. just whitespace). */
	if (tal_count(toks) == 0) {
		buf->used = 0;
		goto read_more;
	}

	buf->output = parse_request(buf, toks);
	if (!buf->output)
		return io_close();

	/* Remove first {}. */
	memmove(buf->buffer, buf->buffer + toks[0].end,
		tal_count(buf->buffer) - toks[0].end);
	buf->used -= toks[0].end;
	tal_free(toks);

	/* Write output, then return as if we read 0 bytes to go again. */
	buf->len_read = 0;
	return io_write(buf->output, strlen(buf->output), read_json, buf);

read_more:
	tal_free(toks);
	buf->len_read = tal_count(buf->buffer) - buf->used;
	return io_read_partial(buf->buffer + buf->used,
			       &buf->len_read, read_json, buf);
}

static void init_rpc(int fd, struct state *state)
{
	struct json_buf *buf;
	struct io_conn *conn;

	buf = tal(state, struct json_buf);
	buf->state = state;
	buf->used = 0;
	buf->len_read = 64;
	buf->buffer = tal_arr(buf, char, buf->len_read);
	buf->output = NULL;

	conn = io_new_conn(fd,
			   io_read_partial(buf->buffer, &buf->len_read,
					   read_json, buf));
	io_set_finish(conn, free_buf, buf);
}


static void rpc_connected(int fd, struct state *state)
{
	log_info(state->log, "Connected json input");

	init_rpc(fd, state);
}

void setup_jsonrpc(struct state *state, const char *rpc_filename)
{
	struct sockaddr_un addr;
	int fd, old_umask;

	if (streq(rpc_filename, ""))
		return;

	if (streq(rpc_filename, "/dev/tty")) {
		fd = open(rpc_filename, O_RDWR);
		if (fd == -1)
			err(1, "Opening %s", rpc_filename);
		init_rpc(fd, state);
		return;
	}

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (strlen(rpc_filename) + 1 > sizeof(addr.sun_path))
		errx(1, "rpc filename '%s' too long", rpc_filename);
	strcpy(addr.sun_path, rpc_filename);
	addr.sun_family = AF_UNIX;

	/* Of course, this is racy! */
	if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0)
		errx(1, "rpc filename '%s' in use", rpc_filename);
	unlink(rpc_filename);

	/* This file is only rw by us! */
	old_umask = umask(0177);
	if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)))
		err(1, "Binding rpc socket to '%s'", rpc_filename);
	umask(old_umask);

	if (listen(fd, 1) != 0)
		err(1, "Listening on '%s'", rpc_filename);

	io_new_listener(fd, rpc_connected, state);
}
