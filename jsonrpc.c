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

struct json_output {
	struct list_node list;
	const char *json;
};

static void free_jcon(struct io_conn *conn, struct json_connection *jcon)
{
	log_info(jcon->state->log, "Closing json input (%s)", strerror(errno));
	tal_free(jcon);
}

struct command {
	const char *name;
	char *(*dispatch)(struct json_connection *jcon,
			  const jsmntok_t *params,
			  char **response);
	const char *description;
	const char *help;
};

static char *json_help(struct json_connection *jcon,
		       const jsmntok_t *params,
		       char **response);

static char *json_echo(struct json_connection *jcon,
		       const jsmntok_t *params,
		       char **response)
{
	json_object_start(response, NULL);
	json_add_num(response, "num", params->size);
	json_add_literal(response, "echo",
			 json_tok_contents(jcon->buffer, params),
			 json_tok_len(params));
	json_object_end(response);
	return NULL;
}

static const struct command cmdlist[] = {
	{ "help", json_help, "describe commands",
	  "[<command>] if specified gives details about a single command." },
	/* Developer/debugging options. */
	{ "dev-echo", json_echo, "echo parameters",
	  "Simple echo test for developers" },
};

static char *json_help(struct json_connection *jcon,
		       const jsmntok_t *params,
		       char **response)
{
	unsigned int i;

	json_array_start(response, NULL);
	for (i = 0; i < ARRAY_SIZE(cmdlist); i++) {
		json_add_object(response,
				"command", JSMN_STRING,
				cmdlist[i].name,
				"description", JSMN_STRING,
				cmdlist[i].description,
				NULL);
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
static char *parse_request(struct json_connection *jcon, const jsmntok_t tok[])
{
	const jsmntok_t *method, *id, *params;
	const struct command *cmd;
	char *result, *error;

	if (tok[0].type != JSMN_OBJECT) {
		log_unusual(jcon->state->log, "Expected {} for json command");
		return NULL;
	}

	method = json_get_member(jcon->buffer, tok, "method");
	params = json_get_member(jcon->buffer, tok, "params");
	id = json_get_member(jcon->buffer, tok, "id");

	if (!id || !method || !params) {
		log_unusual(jcon->state->log, "json: No %s",
			    !id ? "id" : (!method ? "method" : "params"));
		return NULL;
	}

	if (id->type != JSMN_STRING && id->type != JSMN_PRIMITIVE) {
		log_unusual(jcon->state->log,
			    "Expected string/primitive for id");
		return NULL;
	}

	if (method->type != JSMN_STRING) {
		log_unusual(jcon->state->log, "Expected string for method");
		return NULL;
	}

	cmd = find_cmd(jcon->buffer, method);
	if (!cmd) {
		return tal_fmt(jcon,
			      "{ \"result\" : null,"
			      " \"error\" : \"Unknown command '%.*s'\","
			      " \"id\" : %.*s }\n",
			      (int)(method->end - method->start),
			      jcon->buffer + method->start,
			      json_tok_len(id),
			      json_tok_contents(jcon->buffer, id));
	}

	if (params->type != JSMN_ARRAY && params->type != JSMN_OBJECT) {
		log_unusual(jcon->state->log,
			    "Expected array or object for params");
		return NULL;
	}

	result = tal_arr(jcon, char, 0);
	error = cmd->dispatch(jcon, params, &result);
	if (error)
		return tal_fmt(jcon,
			      "{ \"result\" : null,"
			      " \"error\" : \"%s\","
			      " \"id\" : %.*s }\n",
			      error,
			      json_tok_len(id),
			      json_tok_contents(jcon->buffer, id));
	return tal_fmt(jcon,
		       "{ \"result\" : %s,"
		       " \"error\" : null,"
		       " \"id\" : %.*s }\n",
		       result,
		       json_tok_len(id),
		       json_tok_contents(jcon->buffer, id));
}

static struct io_plan write_json(struct io_conn *conn,
				 struct json_connection *jcon)
{
	struct json_output *out;
	
	out = list_pop(&jcon->output, struct json_output, list);
	if (!out)
		return io_wait(jcon, write_json, jcon);

	jcon->outbuf = tal_steal(jcon, out->json);
	tal_free(out);
		
	return io_write(jcon->outbuf, strlen(jcon->outbuf), write_json, jcon);
}

static struct io_plan read_json(struct io_conn *conn,
				struct json_connection *jcon)
{
	jsmntok_t *toks;
	bool valid;
	struct json_output *out;

	/* Resize larger if we're full. */
	jcon->used += jcon->len_read;
	if (jcon->used == tal_count(jcon->buffer))
		tal_resize(&jcon->buffer, jcon->used * 2);

	toks = json_parse_input(jcon->buffer, jcon->used, &valid);
	if (!toks) {
		if (!valid) {
			log_unusual(jcon->state->log,
				    "Invalid token in json input: '%.*s'",
				    (int)jcon->used, jcon->buffer);
			return io_close();
		}
		/* We need more. */
		goto read_more;
	}

	/* Empty buffer? (eg. just whitespace). */
	if (tal_count(toks) == 1) {
		jcon->used = 0;
		goto read_more;
	}

	out = tal(jcon, struct json_output);
	out->json = parse_request(jcon, toks);
	if (!out->json)
		return io_close();

	/* Queue for writing, and wake writer. */
	list_add_tail(&jcon->output, &out->list);
	io_wake(jcon);

	/* Remove first {}. */
	memmove(jcon->buffer, jcon->buffer + toks[0].end,
		tal_count(jcon->buffer) - toks[0].end);
	jcon->used -= toks[0].end;

read_more:
	tal_free(toks);
	jcon->len_read = tal_count(jcon->buffer) - jcon->used;
	return io_read_partial(jcon->buffer + jcon->used,
			       &jcon->len_read, read_json, jcon);
}

static void init_rpc(int fd, struct state *state)
{
	struct json_connection *jcon;
	struct io_conn *conn;

	jcon = tal(state, struct json_connection);
	jcon->state = state;
	jcon->used = 0;
	jcon->len_read = 64;
	jcon->buffer = tal_arr(jcon, char, jcon->len_read);
	list_head_init(&jcon->output);

	conn = io_new_conn(fd,
			   io_read_partial(jcon->buffer, &jcon->len_read,
					   read_json, jcon));
	/* Leave writer idle. */
	io_duplex(conn, io_wait(jcon, write_json, jcon));

	io_set_finish(conn, free_jcon, jcon);
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
