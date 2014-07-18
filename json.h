#ifndef PETTYCOIN_JSON_H
#define PETTYCOIN_JSON_H
#include "config.h"
#include "stdbool.h"
#include "stdlib.h"

#define JSMN_STRICT 1
#define JSMN_PARENT_LINKS 1
# include "jsmn/jsmn.h"

/* Include " if it's a string. */
const char *json_tok_contents(const char *buffer, const jsmntok_t *t);

/* Include " if it's a string. */
int json_tok_len(const jsmntok_t *t);

/* Is this a string equal to str? */
bool json_tok_streq(const char *buffer, const jsmntok_t *tok, const char *str);

/* Is this the null primitive? */
bool json_tok_is_null(const char *buffer, const jsmntok_t *tok);

/* Get top-level label. */
const jsmntok_t *json_get_label(const char *buffer, const jsmntok_t tok[],
				const char *label);

/* If input is complete and valid, return tokens. */
jsmntok_t *json_parse_input(const char *input, int len, bool *valid);

/* Creating JSON strings. */
void json_array_start(char **ptr);
void json_array_next(char **ptr);
void json_array_end(char **ptr);

void json_object_start(char **ptr);
void json_object_next(char **ptr);
void json_object_end(char **ptr);

void json_object(char **result, ...);

#endif /* PETTYCOIN_JSON_H */
