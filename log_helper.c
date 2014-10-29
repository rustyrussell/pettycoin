#include "addr.h"
#include "base58.h"
#include "check_tx.h"
#include "ecode_names.h"
#include "hash_tx.h"
#include "input_refs.h"
#include "log.h"
#include "pkt_names.h"
#include "protocol.h"
#include "protocol_net.h"
#include "tx.h"
#include "valgrind.h"
#include <arpa/inet.h>
#include <ccan/time/time.h>
#include <errno.h>
#include <netinet/in.h>
#include <openssl/bn.h>
#include <sys/socket.h>

/* FIXME: Generate from headers! */
void log_add_struct_(struct log *log, const char *structname, const void *ptr)
{
	if (streq(structname, "struct protocol_double_sha")) {
		const struct protocol_double_sha *s
			= check_mem(ptr, sizeof(*s));
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
	} else if (streq(structname, "struct protocol_block_id")) {
		const struct protocol_block_id *b = check_mem(ptr, sizeof(*b));
		log_add_struct(log, struct protocol_double_sha, &b->sha);
	} else if (streq(structname, "struct protocol_tx_id")) {
		const struct protocol_tx_id *t = check_mem(ptr, sizeof(*t));
		log_add_struct(log, struct protocol_double_sha, &t->sha);
	} else if (streq(structname, "struct protocol_net_address")) {
		const struct protocol_net_address *addr
			= check_mem(ptr, sizeof(*addr));
		char str[INET6_ADDRSTRLEN];

		if (inet_ntop(AF_INET6, addr->addr, str, sizeof(str)) == NULL)
			log_add(log, "Unconvertable IPv6 (%s)",
				strerror(errno));
		else
			log_add(log, "%s", str);
		log_add(log, ":%u", le16_to_cpu(addr->port));
		if (le32_to_cpu(addr->time) != 0)
			log_add(log, " (%u seconds old)", 
				(u32)time_now().ts.tv_sec
				- le32_to_cpu(addr->time));
	} else if (streq(structname, "struct protocol_address")) {
		char *addr = pettycoin_to_base58(NULL, true,
						 check_mem(ptr,
							   sizeof(struct protocol_address)),
						 true);
		log_add(log, "%s", addr);
		tal_free(addr);
	} else if (streq(structname, "struct protocol_gateway_payment")) {
		const struct protocol_gateway_payment *gp
			= check_mem(ptr, sizeof(*gp));
		log_add(log, "%u to ", le32_to_cpu(gp->send_amount));
		log_add_struct(log, struct protocol_address, &gp->output_addr);
	} else if (streq(structname, "union protocol_tx")) {
		const union protocol_tx *tx = check_mem(ptr, tx_len(ptr));
		struct protocol_tx_id sha;
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
		case TX_CLAIM: {
			struct protocol_address addr;

			log_add(log, "CLAIM (%s) for %u on tx ",
				feestr, le32_to_cpu(tx->claim.amount));
			log_add_struct(log, struct protocol_tx_id,
				       &tx->claim.input.input);
			log_add(log, " to ");
			pubkey_to_addr(&tx->claim.input_key, &addr);
			log_add_struct(log, struct protocol_address, &addr);
			log_add(log, " ");
			goto known;
		}
		}
		log_add(log, "UNKNOWN(%u) (%s) ", tx_type(tx), feestr);

	known:
		log_add_struct(log, struct protocol_tx_id, &sha);
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
		name = pkt_name(val);
	} else if (streq(enumname, "enum protocol_ecode")) {
		name = ecode_name(val);
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
		case ECODE_INPUT_CLAIM_BAD:
			name = "ECODE_INPUT_CLAIM_BAD"; break;
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
