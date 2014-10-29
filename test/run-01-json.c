#include "../json.c"
#include "../base58.c"
#include "../shadouble.c"
#include "../hex.c"
#include "helper_key.h"

int main(void)
{
	jsmntok_t *toks_arr, *toks_obj,
		*arg1, *arg2, *arg3, *arg4, *arg5;
	const jsmntok_t *arr_params, *obj_params;
	void *ctx;
	bool valid;
	char *cmd_arr, *cmd_obj;
	struct protocol_double_sha sha;
	struct json_result *result;

	ctx = tal(NULL, char);

	cmd_arr = tal_strdup(ctx,
			     "{ \"method\" : \"dev-echo\", "
			     "\"params\" : [ null, [ 1, 2, 3 ], { \"one\" : 1 }, \"four\" ], "
			     "\"id\" : \"1\" }");

	cmd_obj = tal_strdup(ctx,
			     "{ \"method\" : \"dev-echo\", "
			     "\"params\" : { \"arg2\" : [ 1, 2, 3 ],"
				" \"arg3\" : { \"one\" : 1 },"
				" \"arg4\" : \"four\" }, "
			     "\"id\" : \"1\" }");

	/* Partial id we skip } */
	toks_arr = json_parse_input(cmd_arr, strlen(cmd_arr) - 1, &valid);
	assert(!toks_arr);
	assert(valid);
	toks_obj = json_parse_input(cmd_obj, strlen(cmd_obj) - 1, &valid);
	assert(!toks_obj);
	assert(valid);

	/* This should work */
	toks_arr = json_parse_input(cmd_arr, strlen(cmd_arr), &valid);
	assert(toks_arr);
	assert(tal_count(toks_arr) == 17);
	assert(valid);
	toks_obj = json_parse_input(cmd_obj, strlen(cmd_obj), &valid);
	assert(toks_obj);
	assert(tal_count(toks_obj) == 19);
	assert(valid);

	assert(toks_arr[0].type == JSMN_OBJECT);
	assert(json_tok_len(toks_arr) == strlen(cmd_arr));
	assert(strncmp(json_tok_contents(cmd_arr, toks_arr), cmd_arr,
		       json_tok_len(toks_arr)) == 0);

	assert(toks_obj[0].type == JSMN_OBJECT);
	assert(json_tok_len(toks_obj) == strlen(cmd_obj));
	assert(strncmp(json_tok_contents(cmd_obj, toks_obj), cmd_obj,
		       json_tok_len(toks_obj)) == 0);

	/* It's not a string, so this will fail. */
	assert(!json_tok_streq(cmd_arr, toks_arr, cmd_obj));
	assert(json_tok_streq(cmd_arr, toks_arr+1, "method"));
	assert(json_tok_streq(cmd_obj, toks_obj+1, "method"));

	assert(json_tok_is_null(cmd_arr, toks_arr + 5));
	assert(!json_tok_is_null(cmd_arr, toks_arr + 6));
	assert(!json_tok_is_null(cmd_arr, toks_arr + 7));

	assert(json_get_member(cmd_arr, toks_arr, "method") == toks_arr+2);
	assert(json_get_member(cmd_obj, toks_obj, "method") == toks_obj+2);
	assert(!json_get_member(cmd_arr, toks_arr, "dev-echo"));
	assert(!json_get_member(cmd_obj, toks_obj, "arg2"));

	arr_params = json_get_member(cmd_arr, toks_arr, "params");
	assert(arr_params == toks_arr+4);
	assert(arr_params->type == JSMN_ARRAY);
	obj_params = json_get_member(cmd_obj, toks_obj, "params");
	assert(obj_params == toks_obj+4);
	assert(obj_params->type == JSMN_OBJECT);

	assert(json_get_member(cmd_arr, toks_arr, "id") == toks_arr+15);
	assert(json_get_member(cmd_obj, toks_obj, "id") == toks_obj+17);

	/* get_member works in sub objects */
	assert(json_get_member(cmd_obj, obj_params, "arg4") == toks_obj + 15);

	json_get_params(cmd_arr, arr_params,
			"arg1", &arg1,
			"arg2", &arg2,
			"arg3", &arg3,
			"arg4", &arg4,
			"arg5", &arg5,
			NULL);
	assert(arg1 == NULL);
	assert(arg2 == toks_arr + 6);
	assert(arg2->type == JSMN_ARRAY);
	assert(arg3 == toks_arr + 10);
	assert(arg3->type == JSMN_OBJECT);
	assert(arg4 == toks_arr + 13);
	assert(arg4->type == JSMN_STRING);
	assert(arg5 == NULL);

	json_get_params(cmd_obj, obj_params,
			"arg1", &arg1,
			"arg2", &arg2,
			"arg3", &arg3,
			"arg4", &arg4,
			"arg5", &arg5,
			NULL);
	assert(arg1 == NULL);
	assert(arg2 == toks_obj + 6);
	assert(arg2->type == JSMN_ARRAY);
	assert(arg3 == toks_obj + 11);
	assert(arg3->type == JSMN_OBJECT);
	assert(arg4 == toks_obj + 15);
	assert(arg4->type == JSMN_STRING);	
	assert(arg5 == NULL);

	/* Test json_delve() */
	assert(json_delve(cmd_arr, toks_arr, ".method") == toks_arr + 2);
	assert(json_delve(cmd_arr, toks_arr, ".params[0]") == toks_arr + 5);
	assert(json_delve(cmd_arr, toks_arr, ".params[1]") == toks_arr + 6);
	assert(json_delve(cmd_arr, toks_arr, ".params[2]") == toks_arr + 10);
	assert(json_delve(cmd_arr, toks_arr, ".params[1][2]") == toks_arr + 9);
	assert(json_delve(cmd_arr, toks_arr, ".params[4]") == NULL);
	assert(json_delve(cmd_arr, toks_arr, ".params[1][4]") == NULL);
	assert(json_delve(cmd_arr, toks_arr, ".params[3][4]") == NULL);
	assert(json_delve(cmd_arr, toks_arr, ".unknown") == NULL);
	assert(json_delve(cmd_arr, toks_arr, ".unknown[1]") == NULL);
	assert(json_delve(cmd_arr, toks_arr, ".param") == NULL);
	assert(json_delve(cmd_arr, toks_arr, ".params\"") == NULL);
	assert(json_delve(cmd_arr, toks_arr, ".dev-echo") == NULL);
	assert(json_delve(cmd_arr, toks_arr, ".id[0]") == NULL);

	assert(json_delve(cmd_obj, toks_obj, ".params.arg3.one")
	       == toks_obj + 13);

	/* More exotic object creation */
	result = new_json_result(ctx);
	json_add_object(result,
			"arg2", JSMN_ARRAY, "[ 1, 2, 3 ]",
			"arg3", JSMN_OBJECT, "{ \"one\" : 1 }",
			"arg4", JSMN_STRING, "four",
			NULL);
	assert(streq(json_result_string(result),
		     "{ \"arg2\" : [ 1, 2, 3 ],"
		     " \"arg3\" : { \"one\" : 1 },"
		     " \"arg4\" : \"four\" }"));

	result = new_json_result(ctx);
	json_object_start(result, NULL);

	json_add_pubkey(result, "key", helper_public_key(0));
	memset(&sha, 42, sizeof(sha));
	json_add_double_sha(result, "sha", &sha);
	json_add_address(result, "test-address", true, helper_addr(0));
	json_add_address(result, "address", false, helper_addr(0));
	json_object_end(result);

	assert(streq(json_result_string(result), "{ \"key\" : \"0214f24666a59e62c8b92a0b4b58f2a1cdeb573ea377e42f411be028292ff81926\","
		     " \"sha\" : \"2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a\","
		     " \"test-address\" : \"qKCafy33t92L9Nmoxx8H6NHDuiyGViqWBZ\","
		     " \"address\" : \"PZZyf1xcSbNFodrGQ6ot4LrsdSUu1bgmkc\" }"));
	tal_free(ctx);
	return 0;
}
