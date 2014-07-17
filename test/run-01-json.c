#include <stdio.h>
#include <stdarg.h>
#include <ccan/tal/str/str.h>

static char *output;

static void my_vprintf(const char *fmt, va_list ap)
{
	if (output)
		tal_append_vfmt(&output, fmt, ap);
	else
		output = tal_vfmt(NULL, fmt, ap);
}

static void my_printf(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	my_vprintf(fmt, ap);
	va_end(ap);
}

#define printf my_printf
#define vprintf my_vprintf

#include "../log.h"

#undef log_unusual
#undef log_debug
#define log_unusual(...)
#define log_debug(...)

#include "../json.c"

void test(const char *input, const char *expect, bool needs_more)
{
	struct json_buf *buf = tal(NULL, struct json_buf);
	struct io_plan plan;

	buf->used = 0;
	buf->len = strlen(input);
	buf->buffer = tal_dup(buf, char, input, strlen(input), 0);

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
		assert(buf->used == 0);
		assert(plan.next == (void *)read_json);
		assert(output && streq(output, expect));
	}

	output = tal_free(output);
	tal_free(buf);
}	

int main(void)
{
	unsigned int i;
	const char *cmd, *result;
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
		test(cmd, NULL, true);
		tal_free(cmd);
	}

	test(echocmd, echoresult, false);

	/* Two commands at once will also work. */
	cmd = tal_fmt(NULL, "%s%s", echocmd, echocmd);
	result = tal_fmt(NULL, "%s%s", echoresult, echoresult);

	test(cmd, result, false);
	tal_free(cmd);
	tal_free(result);

	/* Unknown method. */
	test("{ \"method\" : \"unknown\", "
	     "\"params\" : [ \"hello\", \"Arabella!\" ], "
	     "\"id\" : \"2\" }",
	     "{ \"result\" : null, "
	     "\"error\" : \"Unknown command 'unknown'\", \"id\" : \"2\" }\n",
	     false);

	/* Missing parts, will fail. */
	test("{ \"params\" : [ \"hello\", \"Arabella!\" ], "
	     "\"id\" : \"2\" }", NULL, false);
	test("{ \"method\" : \"echo\", "
	     "\"id\" : \"2\" }", NULL, false);
	test("{ \"method\" : \"echo\", "
	     "\"params\" : [ \"hello\", \"Arabella!\" ] }", NULL, false);

	/* It doesn't help to have them in successive commands. */
	test("{ \"params\" : [ \"hello\", \"Arabella!\" ], "
	     "\"id\" : \"2\" }"
	     "{ \"method\" : \"unknown\", "
	     "\"params\" : [ \"hello\", \"Arabella!\" ], "
	     "\"id\" : \"2\" }", NULL, false);

	return 0;
}
