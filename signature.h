#ifndef PETTYCOIN_SIGNATURES_H
#define PETTYCOIN_SIGNATURES_H
#include "config.h"
#include "protocol.h"
#include <openssl/ec.h>
#include <stdbool.h>

bool check_tx_sign(const union protocol_tx *tx,
		   const struct protocol_pubkey *key);

bool sign_tx(union protocol_tx *tx, EC_KEY *private_key);
#endif /* PETTYCOIN_SIGNATURES_H */
