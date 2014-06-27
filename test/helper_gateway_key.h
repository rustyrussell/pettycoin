#ifndef HELPER_GATEWAY_KEY_H
#define HELPER_GATEWAY_KEY_H
#include <ccan/tal/tal.h>
#include <openssl/ec.h>

EC_KEY *helper_gateway_key(const tal_t *ctx);
const struct protocol_pubkey *helper_gateway_public_key();

#endif /* HELPER_GATEWAY_KEY_H */
