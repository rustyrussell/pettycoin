#include <stdio.h>
#include <stdarg.h>
#include <ccan/io/io.h>
#include <ccan/tal/tal.h>

#undef io_close
#define io_close(conn) NULL
#undef io_read_partial
#define io_read_partial(conn, buf, size, lenp, next, jcon) ((void *)jcon)

#include "../jsonrpc.c"
#include "../json.c"
#include "../minimal_log.c"

/* AUTOGENERATED MOCKS START */
/* Generated stub for getblock_command */
const struct json_command getblock_command;
/* Generated stub for getblockhash_command */
const struct json_command getblockhash_command;
/* Generated stub for getinfo_command */
const struct json_command getinfo_command;
/* Generated stub for listtodo_command */
const struct json_command listtodo_command;
/* Generated stub for listtransactions_command */
const struct json_command listtransactions_command;
/* Generated stub for pettycoin_to_base58 */
char *pettycoin_to_base58(const tal_t *ctx, bool test_net,
			  const struct protocol_address *addr,
			  bool bitcoin_style)
{ fprintf(stderr, "pettycoin_to_base58 called!\n"); abort(); }
/* Generated stub for sendrawtransaction_command */
const struct json_command sendrawtransaction_command;
/* Generated stub for submitblock_command */
const struct json_command submitblock_command;
/* Generated stub for to_hex */
char *to_hex(const tal_t *ctx, const void *buf, size_t bufsize)
{ fprintf(stderr, "to_hex called!\n"); abort(); }
/* AUTOGENERATED MOCKS END */

static void test(const char *input, const char *expect, bool needs_more, bool extra)
{
	struct state state;
	struct json_connection *jcon = tal(NULL, struct json_connection);
	void *plan;

	jcon->used = 0;
	jcon->len_read = strlen(input);
	jcon->buffer = tal_dup(jcon, char, input, strlen(input), 0);
	jcon->state = &state;
	list_head_init(&jcon->output);

	plan = read_json(NULL, jcon);
	if (needs_more) {
		/* Should have done partial read for rest. */
		assert(plan == (void *)jcon);
		assert(jcon->used == strlen(input));
		assert(list_empty(&jcon->output));
	} else if (!expect) {
		/* Should have returned io_close. */
		assert(plan == NULL);
	} else {
		/* Should have finished. */
		assert(plan == (void *)jcon);
		assert(!list_empty(&jcon->output));
		assert(streq(list_pop(&jcon->output, struct json_output, list)
			     ->json, expect));
		if (!extra)
			assert(list_empty(&jcon->output));
		else
			assert(streq(list_pop(&jcon->output,
						      struct json_output, list)
				     ->json, expect));
	}
	tal_free(jcon);
}	

int main(void)
{
	unsigned int i;
	const char *cmd;
	const char echocmd[] = "{ \"method\" : \"dev-echo\", "
		"\"params\" : [ \"hello\", \"Arabella!\" ], "
		"\"id\" : \"1\" }";
	const char echoresult[]
		= "{ \"result\" : { \"num\" : 2,"
		" \"echo\" : [ \"hello\", \"Arabella!\" ] }, "
		"\"error\" : null, \"id\" : \"1\" }\n";

	/* Make partial commands work. */
	for (i = 1; i < strlen(echocmd); i++) {
		cmd = tal_strndup(NULL, echocmd, i);
		test(cmd, NULL, true, false);
		tal_free(cmd);
	}

	test(echocmd, echoresult, false, false);

	/* Two commands at once will also work (both processed) */
	cmd = tal_fmt(NULL, "%s%s", echocmd, echocmd);

	test(cmd, echoresult, false, true);
	tal_free(cmd);

	/* Unknown method. */
	test("{ \"method\" : \"unknown\", "
	     "\"params\" : [ \"hello\", \"Arabella!\" ], "
	     "\"id\" : \"2\" }",
	     "{ \"result\" : null, "
	     "\"error\" : \"Unknown command 'unknown'\", \"id\" : \"2\" }\n",
	     false, false);

	/* Missing parts, will fail. */
	test("{ \"params\" : [ \"hello\", \"Arabella!\" ], "
	     "\"id\" : \"2\" }", NULL, false, false);
	test("{ \"method\" : \"echo\", "
	     "\"id\" : \"2\" }", NULL, false, false);
	test("{ \"method\" : \"echo\", "
	     "\"params\" : [ \"hello\", \"Arabella!\" ] }", NULL, false, false);

	/* It doesn't help to have them in successive commands. */
	test("{ \"params\" : [ \"hello\", \"Arabella!\" ], "
	     "\"id\" : \"2\" }"
	     "{ \"method\" : \"unknown\", "
	     "\"params\" : [ \"hello\", \"Arabella!\" ], "
	     "\"id\" : \"2\" }", NULL, false, false);

	return 0;
}
