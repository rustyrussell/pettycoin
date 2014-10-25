#ifndef PETTYCOIN_JSON_ADD_TX_H
#define PETTYCOIN_JSON_ADD_TX_H

struct state;
union protocol_tx;
struct block;
struct json_result;

void json_add_tx(struct json_result *response, const char *fieldname,
		 struct state *state,
		 const union protocol_tx *tx,
		 const struct block *block,
		 unsigned int confirms);

#endif /* PETTYCOIN_JSON_ADD_TX_H */
