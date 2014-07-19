#include <stdio.h>
#include <stdarg.h>
#include <ccan/io/io.h>
#include <ccan/tal/tal.h>

static char *output;

#undef io_write
#define io_write(buffer, len, next, data)	\
	save_io_write(buffer, len, next, data)

static struct io_plan save_io_write(const void *data,
				    size_t size,
				    void *cb,
				    void *arg)
{
	size_t len;

	if (output) {
		len = tal_count(output);
		tal_resize(&output, len + size + 1);
	} else {
		len = 0;
		output = tal_arr(NULL, char, size + 1);
	}
	memcpy(output + len, data, size);
	output[len + size] = '\0';
	return io_always(cb, arg);
}

#include "../log.h"

#undef log_unusual
#undef log_info
#define log_unusual(...)
#define log_info(...)

#include "../jsonrpc.c"
#include "../json.c"

void test(const char *input, const char *expect, bool needs_more, int extra)
{
	struct json_buf *buf = tal(NULL, struct json_buf);
	struct io_plan plan;

	buf->used = 0;
	buf->len_read = strlen(input);
	buf->buffer = tal_dup(buf, char, input, strlen(input), 0);
	buf->output = NULL;

	plan = read_json(NULL, buf);
	if (needs_more) {
		/* Should have done partial read for rest. */
		assert(buf->used == strlen(input));
		assert(plan.next == (void *)read_json);
		assert(plan.u1.cp == buf->buffer + strlen(input));
	} else if (!expect) {
		/* Should have returned io_close. */
		assert(plan.next == NULL);
	} else {
		/* Should have finished. */
		assert(buf->used == extra);
		assert(plan.next == (void *)read_json);
		assert(output && streq(output, expect));
	}

	output = tal_free(output);
	tal_free(buf);
}	

int main(void)
{
	unsigned int i;
	const char *cmd;
	const char echocmd[] = "{ \"method\" : \"echo\", "
		"\"params\" : [ \"hello\", \"Arabella!\" ], "
		"\"id\" : \"1\" }";
	const char echoresult[]
		= "{ \"result\" : { \"num\" : 2,"
		" [ \"hello\", \"Arabella!\" ] }, "
		"\"error\" : null, \"id\" : \"1\" }\n";

	/* Make partial commands work. */
	for (i = 1; i < strlen(echocmd); i++) {
		cmd = tal_strndup(NULL, echocmd, i);
		test(cmd, NULL, true, 0);
		tal_free(cmd);
	}

	test(echocmd, echoresult, false, 0);

	/* Two commands at once will also work (second will be left in buf) */
	cmd = tal_fmt(NULL, "%s%s", echocmd, echocmd);

	test(cmd, echoresult, false, strlen(echocmd));
	tal_free(cmd);

	/* Unknown method. */
	test("{ \"method\" : \"unknown\", "
	     "\"params\" : [ \"hello\", \"Arabella!\" ], "
	     "\"id\" : \"2\" }",
	     "{ \"result\" : null, "
	     "\"error\" : \"Unknown command 'unknown'\", \"id\" : \"2\" }\n",
	     false, 0);

	/* Missing parts, will fail. */
	test("{ \"params\" : [ \"hello\", \"Arabella!\" ], "
	     "\"id\" : \"2\" }", NULL, false, 0);
	test("{ \"method\" : \"echo\", "
	     "\"id\" : \"2\" }", NULL, false, 0);
	test("{ \"method\" : \"echo\", "
	     "\"params\" : [ \"hello\", \"Arabella!\" ] }", NULL, false, 0);

	/* It doesn't help to have them in successive commands. */
	test("{ \"params\" : [ \"hello\", \"Arabella!\" ], "
	     "\"id\" : \"2\" }"
	     "{ \"method\" : \"unknown\", "
	     "\"params\" : [ \"hello\", \"Arabella!\" ], "
	     "\"id\" : \"2\" }", NULL, false, 0);

	return 0;
}
