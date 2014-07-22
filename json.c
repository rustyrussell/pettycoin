/* JSON core and helpers */
#include "base58.h"
#include "json.h"
#include "protocol.h"
#include <assert.h>
#include <ccan/tal/str/str.h>
#include <ccan/tal/tal.h>
#include <stdarg.h>
#include <stdio.h>
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

static const jsmntok_t *skip_elem(const jsmntok_t *tok)
{
	const jsmntok_t *t;
	size_t i;

	for (t = tok + 1, i = 0; i < tok->size; i++)
		t = skip_elem(t);

	return t;
}

const jsmntok_t *json_get_member(const char *buffer, const jsmntok_t tok[],
				 const char *label)
{
	const jsmntok_t *t, *end;

	assert(tok->type == JSMN_OBJECT);

	end = skip_elem(tok);
	for (t = tok + 1; t < end; t = skip_elem(t+1))
		if (json_tok_streq(buffer, t, label))
			return t + 1;
		
	return NULL;
}

void json_get_params(const char *buffer, const jsmntok_t param[], ...)
{
	va_list ap;
	const char *name;
	const jsmntok_t **tokptr, *p, *end;

	if (param->type == JSMN_ARRAY) {
		if (param->size == 0)
			p = NULL;
		else
			p = param + 1;
		end = skip_elem(param);
	} else
		assert(param->type == JSMN_OBJECT);

	va_start(ap, param);
	while ((name = va_arg(ap, const char *)) != NULL) {
		tokptr = va_arg(ap, const jsmntok_t **);
		if (param->type == JSMN_ARRAY) {
			*tokptr = p;
			if (p) {
				p = skip_elem(p);
				if (p == end)
					p = NULL;
			}
		} else {
			*tokptr = json_get_member(buffer, param, name);
		}
		/* Convert 'null' to NULL */
		if (*tokptr
		    && (*tokptr)->type == JSMN_PRIMITIVE
		    && buffer[(*tokptr)->start] == 'n') {
			*tokptr = NULL;
		}
	}

	va_end(ap);
}

jsmntok_t *json_parse_input(const char *input, int len, bool *valid)
{
	jsmn_parser parser;
	jsmntok_t *toks;
	jsmnerr_t ret;

	toks = tal_arr(input, jsmntok_t, 10);

again:	
	jsmn_init(&parser);
	ret = jsmn_parse(&parser, input, len, toks, tal_count(toks) - 1);

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
	tal_resize(&toks, ret + 1);
	/* Make sure last one is always referencable. */
	toks[ret].type = -1;
	toks[ret].start = toks[ret].end = toks[ret].size = 0;
	
	return toks;
}

static void json_start_member(char **result, const char *fieldname)
{
	/* Prepend comma if required. */
	if (**result && !strends(*result, "{ ") && !strends(*result, "[ "))
		tal_append_fmt(result, ", ");
	if (fieldname)
		tal_append_fmt(result, "\"%s\" : ", fieldname);
}

void json_array_start(char **ptr, const char *fieldname)
{
	unsigned int indents = strcount(*ptr, "{") + strcount(*ptr, "[")
		- (strcount(*ptr, "]") + strcount(*ptr, "}"));

	json_start_member(ptr, fieldname);
	if (indents) {
		tal_append_fmt(ptr, "\n");
		while (indents--)
			tal_append_fmt(ptr, "\t");
	}
	tal_append_fmt(ptr, "[ ");
}

void json_array_end(char **ptr)
{
	tal_append_fmt(ptr, " ]");
}

void json_object_start(char **ptr, const char *fieldname)
{
	unsigned int indents = strcount(*ptr, "{") + strcount(*ptr, "[")
		- (strcount(*ptr, "]") + strcount(*ptr, "}"));

	json_start_member(ptr, fieldname);
	if (indents) {
		tal_append_fmt(ptr, "\n");
		while (indents--)
			tal_append_fmt(ptr, "\t");
	}
	tal_append_fmt(ptr, "{ ");
}

void json_object_end(char **ptr)
{
	tal_append_fmt(ptr, " }");
}

void json_add_num(char **result, const char *fieldname, unsigned int value)
{
	json_start_member(result, fieldname);
	tal_append_fmt(result, "%u", value);
}

void json_add_literal(char **result, const char *fieldname,
		      const char *literal, int len)
{
	json_start_member(result, fieldname);
	tal_append_fmt(result, "%.*s", len, literal);
}

void json_add_string(char **result, const char *fieldname, const char *value)
{
	json_start_member(result, fieldname);
	tal_append_fmt(result, "\"%s\"", value);
}

void json_add_bool(char **result, const char *fieldname, bool value)
{
	json_start_member(result, fieldname);
	tal_append_fmt(result, value ? "true" : "false");
}

void json_add_null(char **result, const char *fieldname)
{
	json_start_member(result, fieldname);
	tal_append_fmt(result, "null");
}

void json_add_hex(char **result, const char *fieldname, const void *data,
		  size_t len)
{
	char *hex = tal_arr(*result, char, len * 2 + 1);
	const u8 *p = data;
	size_t i;

	for (i = 0; i < len; i++)
		sprintf(hex + i*2, "%02x", p[i]);

	json_add_string(result, fieldname, hex);
	tal_free(hex);
}

void json_add_pubkey(char **result, const char *fieldname,
		     const struct protocol_pubkey *pubkey)
{
	json_add_hex(result, fieldname, pubkey->key, sizeof(pubkey->key));
}

void json_add_double_sha(char **result, const char *fieldname,
			 const struct protocol_double_sha *sha)
{
	json_add_hex(result, fieldname, sha->sha, sizeof(sha->sha));
}

void json_add_address(char **result, const char *fieldname, bool test_net,
		      const struct protocol_address *addr)
{
	char *str = pettycoin_to_base58(*result, test_net, addr, false);

	json_add_string(result, fieldname, str);
	tal_free(str);
}

void json_add_object(char **result, ...)
{
	va_list ap;
	const char *field;

	va_start(ap, result);
	json_object_start(result, NULL);
	while ((field = va_arg(ap, const char *)) != NULL) {
		jsmntype_t type = va_arg(ap, jsmntype_t);
		const char *value = va_arg(ap, const char *);
		if (type == JSMN_STRING)
			json_add_string(result, field, value);
		else
			json_add_literal(result, field, value, strlen(value));
	}
	json_object_end(result);
	va_end(ap);
}
