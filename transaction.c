#include "transaction.h"
#include "addr.h"

bool find_output(union protocol_transaction *trans, u16 output_num,
		 struct protocol_address *addr, u32 *amount)
{
	struct protocol_gateway_payment *out;

	switch (trans->hdr.type) {
	case TRANSACTION_FROM_GATEWAY:
		if (output_num > le16_to_cpu(trans->gateway.num_outputs))
			return false;
		out = get_gateway_outputs(&trans->gateway);
		*addr = out[output_num].output_addr;
		*amount = le32_to_cpu(out[output_num].send_amount);
		return true;
	case TRANSACTION_NORMAL:
		if (output_num == 0) {
			/* Spending the send_amount. */
			*addr = trans->normal.output_addr;
			*amount = le32_to_cpu(trans->normal.send_amount);
			return true;
		} else if (output_num == 1) {
			/* Spending the change. */
			pubkey_to_addr(&trans->normal.input_key, addr);
			*amount = le32_to_cpu(trans->normal.change_amount);
			return true;
		}
		return false;
	}
	abort();
}

