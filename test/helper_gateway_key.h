#ifndef HELPER_GATEWAY_KEY_H
#define HELPER_GATEWAY_KEY_H
#include <openssl/ec.h>

EC_KEY *helper_gateway_key(void);
const struct protocol_pubkey *helper_gateway_public_key(void);

#endif /* HELPER_GATEWAY_KEY_H */
