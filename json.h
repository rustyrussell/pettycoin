#ifndef PETTYCOIN_JSON_H
#define PETTYCOIN_JSON_H
#include "config.h"
#include "stdbool.h"
#include "stdlib.h"

#define JSMN_STRICT 1
# include "jsmn/jsmn.h"

/* Include " if it's a string. */
const char *json_tok_contents(const char *buffer, const jsmntok_t *t);

/* Include " if it's a string. */
int json_tok_len(const jsmntok_t *t);

/* Is this a string equal to str? */
bool json_tok_streq(const char *buffer, const jsmntok_t *tok, const char *str);

/* Is this the null primitive? */
bool json_tok_is_null(const char *buffer, const jsmntok_t *tok);

/* Get the parameters (by position or name).  Followed by pairs
 * of const char *name, const jsmntok_t **ret_ptr, then NULL.
 * *ret_ptr will be set to NULL if it's a literal 'null' or not present.
 */
void json_get_params(const char *buffer, const jsmntok_t param[], ...);

/* Get top-level member. */
const jsmntok_t *json_get_member(const char *buffer, const jsmntok_t tok[],
				 const char *label);

/* If input is complete and valid, return tokens. */
jsmntok_t *json_parse_input(const char *input, int len, bool *valid);

/* Creating JSON strings */

/* '"fieldname" : [ ' or '[ ' if fieldname is NULL */
void json_array_start(char **ptr, const char *fieldname);
/* '"fieldname" : { ' or '{ ' if fieldname is NULL */
void json_object_start(char **ptr, const char *fieldname);
/* ' ], ' */
void json_array_end(char **ptr);
/* ' }, ' */
void json_object_end(char **ptr);

struct protocol_address;
struct protocol_pubkey;
struct protocol_double_sha;

/* '"fieldname" : "value"' or '"value"' if fieldname is NULL*/
void json_add_string(char **result, const char *fieldname, const char *value);
/* '"fieldname" : literal' or 'literal' if fieldname is NULL*/
void json_add_literal(char **result, const char *fieldname,
		      const char *literal, int len);
/* '"fieldname" : value' or 'value' if fieldname is NULL */
void json_add_num(char **result, const char *fieldname, unsigned int value);
/* '"fieldname" : true|false' or 'true|false' if fieldname is NULL */
void json_add_bool(char **result, const char *fieldname, bool value);
/* '"fieldname" : null' or 'null' if fieldname is NULL */
void json_add_null(char **result, const char *fieldname);
/* '"fieldname" : "0189abcdef..."' or "0189abcdef..." if fieldname is NULL */
void json_add_hex(char **result, const char *fieldname, const void *data,
		  size_t len);

/* '"fieldname" : "BASE58..."' or 'BASE58...' if fieldname is NULL */
void json_add_address(char **result, const char *fieldname, bool test_net,
		      const struct protocol_address *addr);
/* '"fieldname" : "pubkey-hex..."' or 'pubkey-kex...' if fieldname is NULL*/
void json_add_pubkey(char **result, const char *fieldname,
		     const struct protocol_pubkey *pubkey);
/* '"fieldname" : "sha-hex..."' or 'sha-kex...' if fieldname is NULL */
void json_add_double_sha(char **result, const char *fieldname,
			 const struct protocol_double_sha *sha);

void json_add_object(char **result, ...);

#endif /* PETTYCOIN_JSON_H */
