/* Code for JSON API */
/* eg: { "method" : "echo", "params" : [ "hello", "Arabella!" ], "id" : "1" } */
#include "json.h"
#include "log.h"
#include "state.h"
#include <ccan/array_size/array_size.h>
#include <ccan/io/io.h>
#include <ccan/tal/str/str.h>
#include <errno.h>
#include <stdio.h>

#define JSMN_STRICT 1
#define JSMN_PARENT_LINKS 1
# include "jsmn/jsmn.c"

struct json_buf {
	struct state *state;
	/* How much is already filled. */
	size_t used;
	/* How much has just been filled. */
	size_t len;
	char *buffer;
};

static void free_buf(struct io_conn *conn, struct json_buf *buf)
{
	/* We never read anything?  stdin probably wasn't open. */
	if (buf->used == 0 && buf->len == 1)
		log_debug(buf->state->log, "Closing unused json input");
	else
		log_unusual(buf->state->log, "Closing json input (%s)",
			    strerror(errno));
	tal_free(buf);
}

struct command {
	const char *name;
	bool (*dispatch)(struct state *state,
			 const char *buffer, const jsmntok_t *id,
			 const jsmntok_t *params);
};

/* Include " if it's a string. */
static const char *token_contents(const char *buffer, const jsmntok_t *t)
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

/* FIXME: Async responses! */
static void json_respond(const char *buffer, const jsmntok_t *id,
			 const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	printf("{ \"result\" : ");
	vprintf(fmt, ap);
	printf(", \"error\" : null, \"id\" : %.*s }\n",
	       token_len(id), token_contents(buffer, id));

	va_end(ap);
}

/* FIXME: async! */
static void json_err(const char *buffer, const jsmntok_t *id,
		     const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	printf("{ \"result\" : null, \"error\" : \"");
	vprintf(fmt, ap);
	printf("\", \"id\" : %.*s }\n",
	       token_len(id), token_contents(buffer, id));

	va_end(ap);
}

static bool json_help(struct state *state,
		      const char *buffer, const jsmntok_t *id,
		      const jsmntok_t *params)
{
	json_respond(buffer, id, "\"Not very helpful, I'm afraid!\"");
	return true;
}

static bool json_echo(struct state *state,
		      const char *buffer, const jsmntok_t *id,
		      const jsmntok_t *params)
{
	json_respond(buffer, id, "{ \"num\" : %u, %.*s }",
		     params->size,
		     token_len(params),
		     token_contents(buffer, params));
	return true;
}

static const struct command cmdlist[] = {
	{ "help", json_help },
	{ "echo", json_echo }
};

static const struct command *find_cmd(const char *str, size_t len)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(cmdlist); i++)
		if (len == strlen(cmdlist[i].name)
		    && strncmp(cmdlist[i].name, str, len) == 0)
			return &cmdlist[i];
	return NULL;
}

static bool tok_streq(const char *buffer, const jsmntok_t *tok,
		      const char *str)
{
	if (tok->type != JSMN_STRING)
		return false;
	return strncmp(buffer + tok->start, str, tok->end - tok->start) == 0;
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

/* Returns false if it's a fatal error. */
static bool parse_request(struct state *state, const char *buffer,
			  const jsmntok_t tok[], size_t num_tok)
{
	const jsmntok_t *method, *id, *params, *t;
	const struct command *cmd;

	if (tok[0].type != JSMN_OBJECT) {
		log_unusual(state->log, "Expected {} for json command");
		return false;
	}

	method = get_label(buffer, tok, num_tok, "method");
	params = get_label(buffer, tok, num_tok, "params");
	id = get_label(buffer, tok, num_tok, "id");

	if (!id || !method || !params) {
		log_unusual(state->log, "json: No %s",
			    !id ? "id" : (!method ? "method" : "params"));
		return false;
	}

	id++;
	if (id->type != JSMN_STRING && id->type != JSMN_PRIMITIVE) {
		log_unusual(state->log, "Expected string/primitive for id");
		return false;
	}

	t = method + 1;
	if (t->type != JSMN_STRING) {
		log_unusual(state->log, "Expected string for method");
		return false;
	}

	cmd = find_cmd(buffer + t->start, t->end - t->start);
	if (!cmd) {
		json_err(buffer, id, "Unknown command '%.*s'",
			 (int)(t->end - t->start), buffer + t->start);
		return true;
	}

	t = params + 1;
	if (t->type != JSMN_ARRAY) {
		log_unusual(state->log, "Expected array after params");
		return false;
	}

	return cmd->dispatch(state, buffer, id, t);
}

static struct io_plan read_json(struct io_conn *conn, struct json_buf *buf)
{
	jsmnerr_t r;
	jsmntok_t *toks = tal_arr(buf, jsmntok_t, 100);
	jsmn_parser parser;

	/* Resize larger if we're full. */
	buf->used += buf->len;
	if (buf->used == tal_count(buf->buffer))
		tal_resize(&buf->buffer, buf->used * 2);

again:
	jsmn_init(&parser);
	r = jsmn_parse(&parser, buf->buffer, buf->used, toks, tal_count(toks));

	switch (r) {
	case JSMN_ERROR_NOMEM:
		tal_resize(&toks, tal_count(toks) * 2);
		goto again;
	case JSMN_ERROR_INVAL:
		log_unusual(buf->state->log,
			    "Invalid token in json input: '%.*s'",
			    (int)buf->used, buf->buffer);
		return io_close();
	case JSMN_ERROR_PART:
		buf->len = tal_count(buf->buffer) - buf->used;
		return io_read_partial(buf->buffer + buf->used, &buf->len,
				       read_json, buf);
	default:
		/* Empty buffer? (eg. just whitespace). */
		if (r == 0) {
			buf->used = 0;
			return io_read_partial(buf->buffer + buf->used,
					       &buf->len, read_json, buf);
		}

		if (!parse_request(buf->state, buf->buffer, toks, r))
			return io_close();

		/* Remove first {}, retry. */
		memmove(buf->buffer, buf->buffer + toks[0].end,
			tal_count(buf->buffer) - toks[0].end);
		buf->used -= toks[0].end;
		goto again;
	}
}

void setup_json(struct state *state)
{
	struct json_buf *buf = tal(state, struct json_buf);
	struct io_conn *conn;

	buf->state = state;
	buf->used = 0;
	buf->len = 1;
	buf->buffer = tal_arr(buf, char, buf->len);

	conn = io_new_conn(STDIN_FILENO,
			   io_read_partial(buf->buffer, &buf->len,
					   read_json, buf));
	io_set_finish(conn, free_buf, buf);
}
