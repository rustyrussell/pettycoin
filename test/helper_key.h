#ifndef HELPER_PRIVATE_KEY_H
#define HELPER_PRIVATE_KEY_H
#include <openssl/ec.h>

EC_KEY *helper_private_key(int idx);
const struct protocol_pubkey *helper_public_key(int idx);
const struct protocol_address *helper_addr(int idx);

#endif /* HELPER_PRIVATE_KEY_H */
