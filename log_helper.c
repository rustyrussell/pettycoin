#include "addr.h"
#include "base58.h"
#include "check_tx.h"
#include "hash_tx.h"
#include "input_refs.h"
#include "log.h"
#include "protocol.h"
#include "protocol_net.h"
#include "tx.h"
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <openssl/bn.h>
#include <sys/socket.h>

/* FIXME: Generate from headers! */
void log_add_struct_(struct log *log, const char *structname, const void *ptr)
{
	if (streq(structname, "struct protocol_double_sha")) {
		const struct protocol_double_sha *s = ptr;
		log_add(log,
			"%02x%02x%02x%02x%02x%02x%02x%02x"
			"%02x%02x%02x%02x%02x%02x%02x%02x"
			"%02x%02x%02x%02x%02x%02x%02x%02x"
			"%02x%02x%02x%02x%02x%02x%02x%02x",
			s->sha[0], s->sha[1], s->sha[2], s->sha[3],
			s->sha[4], s->sha[5], s->sha[6], s->sha[7],
			s->sha[8], s->sha[9], s->sha[10], s->sha[11],
			s->sha[12], s->sha[13], s->sha[14], s->sha[15],
			s->sha[16], s->sha[17], s->sha[18], s->sha[19],
			s->sha[20], s->sha[21], s->sha[22], s->sha[23],
			s->sha[24], s->sha[25], s->sha[26], s->sha[27],
			s->sha[28], s->sha[29], s->sha[30], s->sha[31]);
	} else if (streq(structname, "struct protocol_net_address")) {
		const struct protocol_net_address *addr = ptr;
		char str[INET6_ADDRSTRLEN];

		if (inet_ntop(AF_INET6, addr->addr, str, sizeof(str)) == NULL)
			log_add(log, "Unconvertable IPv6 (%s)",
				strerror(errno));
		else
			log_add(log, "%s", str);
		log_add(log, ":%u", be16_to_cpu(addr->port));
	} else if (streq(structname, "struct protocol_address")) {
		char *addr = pettycoin_to_base58(NULL, true, ptr, true);
		log_add(log, "%s", addr);
		tal_free(addr);
	} else if (streq(structname, "struct protocol_gateway_payment")) {
		const struct protocol_gateway_payment *gp = ptr;
		log_add(log, "%u to ", le32_to_cpu(gp->send_amount));
		log_add_struct(log, struct protocol_address, &gp->output_addr);
	} else if (streq(structname, "union protocol_tx")) {
		const union protocol_tx *tx = ptr;
		struct protocol_double_sha sha;
		struct protocol_address input_addr;
		const char *feestr = tx_pays_fee(tx) ? "fee" : "no fee";
		u32 i;

		hash_tx(tx, &sha);
		switch (tx_type(tx)) {
		case TX_NORMAL:
			log_add(log, "NORMAL (%s) %u inputs => %u (%u change) ",
				feestr,
				le32_to_cpu(tx->normal.num_inputs),
				le32_to_cpu(tx->normal.send_amount),
				le32_to_cpu(tx->normal.change_amount));
			get_tx_input_address(tx, &input_addr);
			log_add(log, " from ");
			log_add_struct(log, struct protocol_address, &input_addr);
			log_add(log, " to ");
			log_add_struct(log, struct protocol_address,
				       &tx->normal.output_addr);
			goto known;
		case TX_FROM_GATEWAY:
			log_add(log, "FROM_GATEWAY (%s) %u outputs",
				feestr,
				le32_to_cpu(tx->from_gateway.num_outputs));
			for (i = 0;
			     i < le32_to_cpu(tx->from_gateway.num_outputs);
			     i++) {
				log_add(log, " %u:", i);
				log_add_struct(log,
					struct protocol_gateway_payment,
					&get_from_gateway_outputs(
						&tx->from_gateway)[i]);
			}
			goto known;
		case TX_TO_GATEWAY:
			log_add(log, "TO_GATEWAY (%s) %u inputs"
				" => %u (%u change) ",
				feestr,
				le32_to_cpu(tx->to_gateway.num_inputs),
				le32_to_cpu(tx->to_gateway.send_amount),
				le32_to_cpu(tx->to_gateway.change_amount));
			get_tx_input_address(tx, &input_addr);
			log_add(log, " from ");
			log_add_struct(log, struct protocol_address, &input_addr);
			log_add(log, " to ");
			log_add_struct(log, struct protocol_address,
				       &tx->to_gateway.to_gateway_addr);
			goto known;
		}
		log_add(log, "UNKNOWN(%u) (%s) ", tx_type(tx), feestr);

	known:
		log_add_struct(log, struct protocol_double_sha, &sha);
	} else if (streq(structname, "BIGNUM")) {
		char *str = BN_bn2hex(ptr);
		log_add(log, "%s", str);
		OPENSSL_free(str);
	} else
		abort();
}

void log_add_enum_(struct log *log, const char *enumname, unsigned val)
{
	const char *name = NULL;
	if (streq(enumname, "enum protocol_pkt_type")) {
		switch ((enum protocol_pkt_type)val) {
		case PROTOCOL_PKT_NONE:
		case PROTOCOL_PKT_MAX:
			break; /* Shouldn't happen! */ 

		case PROTOCOL_PKT_ERR:
			name = "PROTOCOL_PKT_ERR"; break;
		case PROTOCOL_PKT_WELCOME:
			name = "PROTOCOL_PKT_WELCOME"; break;
		case PROTOCOL_PKT_HORIZON:
			name = "PROTOCOL_PKT_HORIZON"; break;
		case PROTOCOL_PKT_SYNC:
			name = "PROTOCOL_PKT_SYNC"; break;
		case PROTOCOL_PKT_GET_CHILDREN:
			name = "PROTOCOL_PKT_GET_CHILDREN"; break;
		case PROTOCOL_PKT_CHILDREN:
			name = "PROTOCOL_PKT_CHILDREN"; break;
		case PROTOCOL_PKT_GET_BLOCK:
			name = "PROTOCOL_PKT_GET_BLOCK"; break;
		case PROTOCOL_PKT_BLOCK:
			name = "PROTOCOL_PKT_BLOCK"; break;
		case PROTOCOL_PKT_GET_SHARD:
			name = "PROTOCOL_PKT_GET_SHARD"; break;
		case PROTOCOL_PKT_SHARD:
			name = "PROTOCOL_PKT_SHARD"; break;

		case PROTOCOL_PKT_SET_FILTER:
			name = "PROTOCOL_PKT_SET_FILTER"; break;
		case PROTOCOL_PKT_TX:
			name = "PROTOCOL_PKT_TX"; break;
		case PROTOCOL_PKT_HASHES_IN_BLOCK:
			name = "PROTOCOL_PKT_HASHES_IN_BLOCK"; break;
		case PROTOCOL_PKT_TX_IN_BLOCK:
			name = "PROTOCOL_PKT_TX_IN_BLOCK"; break;
		case PROTOCOL_PKT_GET_TX:
			name = "PROTOCOL_PKT_GET_TX"; break;
		case PROTOCOL_PKT_GET_TX_IN_BLOCK:
			name = "PROTOCOL_PKT_GET_TX_IN_BLOCK"; break;
		case PROTOCOL_PKT_GET_TXMAP:
			name = "PROTOCOL_PKT_GET_TXMAP"; break;
		case PROTOCOL_PKT_TXMAP:
			name = "PROTOCOL_PKT_TXMAP"; break;
		case PROTOCOL_PKT_TX_BAD_INPUT:
			name = "PROTOCOL_PKT_TX_BAD_INPUT"; break;
		case PROTOCOL_PKT_TX_BAD_AMOUNT:
			name = "PROTOCOL_PKT_TX_BAD_AMOUNT"; break;
		case PROTOCOL_PKT_TX_DOUBLESPEND:
			name = "PROTOCOL_PKT_TX_DOUBLESPEND"; break;
		case PROTOCOL_PKT_COMPLAIN_TX_MISORDER:
			name = "PROTOCOL_PKT_COMPLAIN_TX_MISORDER"; break;
		case PROTOCOL_PKT_COMPLAIN_TX_INVALID:
			name = "PROTOCOL_PKT_COMPLAIN_TX_INVALID"; break;
		case PROTOCOL_PKT_COMPLAIN_TX_BAD_INPUT:
			name = "PROTOCOL_PKT_COMPLAIN_TX_BAD_INPUT"; break;
		case PROTOCOL_PKT_COMPLAIN_DOUBLESPEND:
			name = "PROTOCOL_PKT_COMPLAIN_DOUBLESPEND"; break;
		case PROTOCOL_PKT_COMPLAIN_BAD_INPUT_REF:
			name = "PROTOCOL_PKT_COMPLAIN_BAD_INPUT_REF"; break;
		case PROTOCOL_PKT_COMPLAIN_TX_BAD_AMOUNT:
			name = "PROTOCOL_PKT_COMPLAIN_TX_BAD_AMOUNT"; break;
		case PROTOCOL_PKT_PIGGYBACK:
			name = "PROTOCOL_PKT_PIGGYBACK"; break;
		}
	} else if (streq(enumname, "enum protocol_ecode")) {
		switch ((enum protocol_ecode)val) {
		case PROTOCOL_ECODE_NONE:
			name = "PROTOCOL_ECODE_NONE"; break;
		case PROTOCOL_ECODE_UNKNOWN_COMMAND:
			name = "PROTOCOL_ECODE_UNKNOWN_COMMAND"; break;
		case PROTOCOL_ECODE_UNKNOWN_ERRCODE:
			name = "PROTOCOL_ECODE_UNKNOWN_ERRCODE"; break;
		case PROTOCOL_ECODE_INVALID_LEN:
			name = "PROTOCOL_ECODE_INVALID_LEN"; break;
		case PROTOCOL_ECODE_SHOULD_BE_WAITING:
			name = "PROTOCOL_ECODE_SHOULD_BE_WAITING"; break;
		case PROTOCOL_ECODE_HIGH_VERSION:
			name = "PROTOCOL_ECODE_HIGH_VERSION"; break;
		case PROTOCOL_ECODE_LOW_VERSION:
			name = "PROTOCOL_ECODE_LOW_VERSION"; break;
		case PROTOCOL_ECODE_NO_INTEREST:
			name = "PROTOCOL_ECODE_NO_INTEREST"; break;
		case PROTOCOL_ECODE_BAD_SHARD_ORDER:
			name = "PROTOCOL_ECODE_BAD_SHARD_ORDER"; break;
		case PROTOCOL_ECODE_WRONG_GENESIS:
			name = "PROTOCOL_ECODE_WRONG_GENESIS"; break;
		case PROTOCOL_ECODE_NO_MUTUAL:
			name = "PROTOCOL_ECODE_NO_MUTUAL"; break;
		case PROTOCOL_ECODE_FILTER_INVALID:
			name = "PROTOCOL_ECODE_FILTER_INVALID"; break;
		case PROTOCOL_ECODE_UNKNOWN_BLOCK:
			name = "PROTOCOL_ECODE_UNKNOWN_BLOCK"; break;
		case PROTOCOL_ECODE_UNKNOWN_SHARD:
			name = "PROTOCOL_ECODE_UNKNOWN_SHARD"; break;
		case PROTOCOL_ECODE_UNKNOWN_TX:
			name = "PROTOCOL_ECODE_UNKNOWN_TX"; break;
		case PROTOCOL_ECODE_BAD_TXOFF:
			name = "PROTOCOL_ECODE_BAD_TXOFF"; break;
		case PROTOCOL_ECODE_BAD_SHARDNUM:
			name = "PROTOCOL_ECODE_BAD_SHARDNUM"; break;
		case PROTOCOL_ECODE_BLOCK_HIGH_VERSION:
			name = "PROTOCOL_ECODE_BLOCK_HIGH_VERSION"; break;
		case PROTOCOL_ECODE_BLOCK_LOW_VERSION:
			name = "PROTOCOL_ECODE_BLOCK_LOW_VERSION"; break;
		case PROTOCOL_ECODE_BAD_TIMESTAMP:
			name = "PROTOCOL_ECODE_BAD_TIMESTAMP"; break;
		case PROTOCOL_ECODE_BAD_PREV_TXHASHES:
			name = "PROTOCOL_ECODE_BAD_PREV_TXHASHES"; break;
		case PROTOCOL_ECODE_BAD_DIFFICULTY:
			name = "PROTOCOL_ECODE_BAD_DIFFICULTY"; break;
		case PROTOCOL_ECODE_INSUFFICIENT_WORK:
			name = "PROTOCOL_ECODE_INSUFFICIENT_WORK"; break;
		case PROTOCOL_ECODE_BAD_DEPTH:
			name = "PROTOCOL_ECODE_BAD_DEPTH"; break;
		case PROTOCOL_ECODE_TX_HIGH_VERSION:
			name = "PROTOCOL_ECODE_TX_HIGH_VERSION"; break;
		case PROTOCOL_ECODE_TX_LOW_VERSION:
			name = "PROTOCOL_ECODE_TX_LOW_VERSION"; break;
		case PROTOCOL_ECODE_TX_TYPE_UNKNOWN:
			name = "PROTOCOL_ECODE_TX_TYPE_UNKNOWN"; break;
		case PROTOCOL_ECODE_TX_BAD_GATEWAY:
			name = "PROTOCOL_ECODE_TX_BAD_GATEWAY"; break;
		case PROTOCOL_ECODE_TX_CROSS_SHARDS:
			name = "PROTOCOL_ECODE_TX_CROSS_SHARDS"; break;
		case PROTOCOL_ECODE_TX_TOO_LARGE:
			name = "PROTOCOL_ECODE_TX_TOO_LARGE"; break;
		case PROTOCOL_ECODE_TX_TOO_SMALL:
			name = "PROTOCOL_ECODE_TX_TOO_SMALL"; break;
		case PROTOCOL_ECODE_TX_BAD_SIG:
			name = "PROTOCOL_ECODE_TX_BAD_SIG"; break;
		case PROTOCOL_ECODE_TX_TOO_MANY_INPUTS:
			name = "PROTOCOL_ECODE_TX_TOO_MANY_INPUTS"; break;
		case PROTOCOL_ECODE_BAD_PROOF:
			name = "PROTOCOL_ECODE_BAD_PROOF"; break;
		case PROTOCOL_ECODE_REF_BAD_BLOCKS_AGO:
			name = "PROTOCOL_ECODE_REF_BAD_BLOCKS_AGO"; break;
		case PROTOCOL_ECODE_REF_BAD_SHARD:
			name = "PROTOCOL_ECODE_REF_BAD_SHARD"; break;
		case PROTOCOL_ECODE_REF_BAD_TXOFF:
			name = "PROTOCOL_ECODE_REF_BAD_TXOFF"; break;
		case PROTOCOL_ECODE_BAD_MERKLE:
			name = "PROTOCOL_ECODE_BAD_MERKLE"; break;
		case PROTOCOL_ECODE_BAD_INPUTNUM:
			name = "PROTOCOL_ECODE_BAD_INPUTNUM"; break;
		case PROTOCOL_ECODE_BAD_INPUT:
			name = "PROTOCOL_ECODE_BAD_INPUT"; break;
		case PROTOCOL_ECODE_COMPLAINT_INVALID:
			name = "PROTOCOL_ECODE_COMPLAINT_INVALID"; break;
		case PROTOCOL_ECODE_BAD_MISORDER_POS:
			name = "PROTOCOL_ECODE_BAD_MISORDER_POS"; break;
		case PROTOCOL_ECODE_BAD_DOUBLESPEND_BLOCKS:
			name = "PROTOCOL_ECODE_BAD_DOUBLESPEND_BLOCKS"; break;
		case PROTOCOL_ECODE_PRIV_UNKNOWN_PREV:
			name = "PROTOCOL_ECODE_PRIV_UNKNOWN_PREV"; break;
		case PROTOCOL_ECODE_MAX:
			break; /* Shouldn't happen! */
		}
	} else if (streq(enumname, "enum input_ecode")) {
		switch ((enum input_ecode)val) {
		case ECODE_INPUT_OK:
			name = "ECODE_INPUT_OK"; break;
		case ECODE_INPUT_UNKNOWN:
			name = "ECODE_INPUT_UNKNOWN"; break;
		case ECODE_INPUT_BAD:
			name = "ECODE_INPUT_BAD"; break;
		case ECODE_INPUT_BAD_AMOUNT:
			name = "ECODE_INPUT_BAD_AMOUNT"; break;
		case ECODE_INPUT_DOUBLESPEND:
			name = "ECODE_INPUT_DOUBLESPEND"; break;
		}
	} else if (streq(enumname, "enum ref_ecode")) {
		switch ((enum ref_ecode)val) {
		case ECODE_REF_OK:
			name = "ECODE_REF_OK"; break;
		case ECODE_REF_UNKNOWN:
			name = "ECODE_REF_UNKNOWN"; break;
		case ECODE_REF_BAD_HASH:
			name = "ECODE_REF_BAD_HASH"; break;
		}
	}
	if (name)
		log_add(log, "%s", name);
	else
		log_add(log, "Unknown %s (%u)", enumname, val);
}
