/* JSON core and helpers */
#include "json.h"
#include <ccan/tal/str/str.h>
#include <ccan/tal/tal.h>
#include <stdarg.h>
#include <string.h>

/* We add this by raw include. */
# include "jsmn/jsmn.c"

const char *json_tok_contents(const char *buffer, const jsmntok_t *t)
{
	if (t->type == JSMN_STRING)
		return buffer + t->start - 1;
	return buffer + t->start;
}

/* Include " if it's a string. */
int json_tok_len(const jsmntok_t *t)
{
	if (t->type == JSMN_STRING)
		return t->end - t->start + 2;
	return t->end - t->start;
}

bool json_tok_streq(const char *buffer, const jsmntok_t *tok, const char *str)
{
	if (tok->type != JSMN_STRING)
		return false;
	return strncmp(buffer + tok->start, str, tok->end - tok->start) == 0;
}

bool json_tok_is_null(const char *buffer, const jsmntok_t *tok)
{
	if (tok->type != JSMN_PRIMITIVE)
		return false;
	return buffer[tok->start] == 'n';
}

const jsmntok_t *json_get_label(const char *buffer, const jsmntok_t tok[],
				const char *label)
{
	unsigned int i;

	for (i = 1; i < tal_count(tok); i++) {
		if (tok[i].parent == 0
		    && json_tok_streq(buffer, &tok[i], label))
			return &tok[i];
		/* Another top-level object?  Stop. */
		if (tok[i].parent == -1)
			break;
	}
	return NULL;
}

jsmntok_t *json_parse_input(const char *input, int len, bool *valid)
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
		*valid = false;
	case JSMN_ERROR_PART:
		*valid = true;
		return tal_free(toks);
	case JSMN_ERROR_NOMEM:
		tal_resize(&toks, tal_count(toks) * 2);
		goto again;
	}

	/* Cut to length and return. */
	*valid = true;
	tal_resize(&toks, ret);
	return toks;
}

void json_array_start(char **ptr)
{
	unsigned int indents = strcount(*ptr, "{") + strcount(*ptr, "[")
		- (strcount(*ptr, "]") + strcount(*ptr, "}"));

	if (indents) {
		tal_append_fmt(ptr, "\n");
		while (indents--)
			tal_append_fmt(ptr, "\t");
	}

	tal_append_fmt(ptr, "[ ");
}

void json_array_next(char **ptr)
{
	tal_append_fmt(ptr, ", ");
}

void json_array_end(char **ptr)
{
	/* Undo last json_array_next */
	if (strends(*ptr, ", "))
		(*ptr)[strlen(*ptr) - 2] = '\0';
	tal_append_fmt(ptr, " ]");
}

void json_object_start(char **ptr)
{
	unsigned int indents = strcount(*ptr, "{") + strcount(*ptr, "[")
		- (strcount(*ptr, "]") + strcount(*ptr, "}"));

	if (indents) {
		tal_append_fmt(ptr, "\n");
		while (indents--)
			tal_append_fmt(ptr, "\t");
	}
	tal_append_fmt(ptr, "{ ");
}

void json_object_next(char **ptr)
{
	tal_append_fmt(ptr, ", ");
}

void json_object_end(char **ptr)
{
	/* Undo last json_object_next */
	if (strends(*ptr, ", "))
		(*ptr)[strlen(*ptr) - 2] = '\0';
	tal_append_fmt(ptr, " }");
}

void json_object(char **result, ...)
{
	va_list ap;
	const char *field;

	va_start(ap, result);
	json_object_start(result);
	while ((field = va_arg(ap, const char *)) != NULL) {
		const char *value = va_arg(ap, const char *);
		jsmntype_t type = va_arg(ap, jsmntype_t);
		if (type == JSMN_STRING)
			tal_append_fmt(result, "\"%s\" : \"%s\"", field, value);
		else
			tal_append_fmt(result, "\"%s\" : %s", field, value);
		json_object_next(result);
	}
	json_object_end(result);
	va_end(ap);
}
