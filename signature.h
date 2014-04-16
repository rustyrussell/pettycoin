#ifndef PETTYCOIN_SIGNATURES_H
#define PETTYCOIN_SIGNATURES_H
#include "protocol.h"
#include <openssl/ec.h>
#include <stdbool.h>

bool check_trans_sign(const union protocol_transaction *t,
		      const struct protocol_pubkey *key,
		      const struct protocol_signature *signature);

bool sign_transaction(union protocol_transaction *t, EC_KEY *private_key);
#endif /* PETTYCOIN_SIGNATURES_H */
