#include "block.h"
#include "hash_tx.h"
#include "json.h"
#include "json_add_tx.h"
#include "state.h"
#include "tx.h"

static void json_add_input(char **response, const char *fieldname,
			   const struct protocol_input *inp)
{
	json_object_start(response, fieldname);
	json_add_double_sha(response, "input", &inp->input);
	json_add_num(response, "output", le16_to_cpu(inp->output));
	json_object_end(response);
}

static void json_add_inputs(char **response, const union protocol_tx *tx)
{
	unsigned int i;

	json_array_start(response, "vin");
	for (i = 0; i < num_inputs(tx); i++)
		json_add_input(response, NULL, tx_input(tx, i));
	json_array_end(response);
}

static void json_add_outputs(char **response,
			     struct state *state, const union protocol_tx *tx)
{
	unsigned int i;
	struct protocol_gateway_payment *outputs;

	outputs = get_from_gateway_outputs(&tx->from_gateway);

	json_array_start(response, "vout");
	for (i = 0; i < num_outputs(tx); i++) {
		json_object_start(response, NULL);
		json_add_num(response, "send_amount",
			 le32_to_cpu(outputs[i].send_amount));
		json_add_address(response, "output_addr", state->test_net,
				 &outputs[i].output_addr);
		json_object_end(response);
	}
	json_array_end(response);
}

void json_add_tx(char **response, const char *fieldname,
		 struct state *state,
		 const union protocol_tx *tx,
		 const struct block *block,
		 unsigned int confirms)
{
	struct protocol_double_sha sha;

	json_object_start(response, fieldname);
	hash_tx(tx, &sha);
	json_add_double_sha(response, "txid", &sha);
	if (block)
		json_add_double_sha(response, "block", &block->sha);
	json_add_num(response, "confirmations", confirms);
	json_add_num(response, "version", tx->hdr.version);
	json_add_num(response, "features", tx->hdr.features);

	switch (tx_type(tx)) {
	case TX_NORMAL:
		json_add_string(response, "type", "TX_NORMAL");
		json_add_pubkey(response, "input_key", &tx->normal.input_key);
		json_add_address(response, "output_addr",
				 state->test_net, &tx->normal.output_addr);
		json_add_num(response, "send_amount",
			     le32_to_cpu(tx->normal.send_amount));
		json_add_num(response, "change_amount",
			     le32_to_cpu(tx->normal.change_amount));
		json_add_signature(response, "signature",
				   &tx->normal.signature);
		json_add_inputs(response, tx);
		goto finish;
	case TX_FROM_GATEWAY:
		json_add_string(response, "type", "TX_FROM_GATEWAY");
		json_add_pubkey(response, "gateway_key",
				&tx->from_gateway.gateway_key);
		json_add_signature(response, "signature",
				   &tx->normal.signature);
		json_add_outputs(response, state, tx);
		goto finish;
	case TX_TO_GATEWAY:
		json_add_string(response, "type", "TX_TO_GATEWAY");
		json_add_pubkey(response, "input_key",
				&tx->to_gateway.input_key);
		json_add_address(response, "output_addr",
				 state->test_net,
				 &tx->to_gateway.to_gateway_addr);
		json_add_num(response, "send_amount",
			     le32_to_cpu(tx->to_gateway.send_amount));
		json_add_num(response, "change_amount",
			     le32_to_cpu(tx->to_gateway.change_amount));
		json_add_signature(response, "signature",
				   &tx->to_gateway.signature);
		json_add_inputs(response, tx);
		goto finish;
	case TX_CLAIM:
		json_add_string(response, "type", "TX_CLAIM");
		json_add_pubkey(response, "input_key", &tx->claim.input_key);
		json_add_num(response, "amount", le32_to_cpu(tx->claim.amount));
		json_add_signature(response, "claim", &tx->claim.signature);
		json_add_input(response, "input", &tx->claim.input);
		goto finish;
	}
	abort();

finish:
	json_object_end(response);
}

