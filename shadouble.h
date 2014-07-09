#ifndef PETTYCOIN_SHADOUBLE_H
#define PETTYCOIN_SHADOUBLE_H
#include "config.h"
#include <openssl/sha.h>

struct protocol_double_sha;
void SHA256_Double_Final(SHA256_CTX *ctx, struct protocol_double_sha *sha);
#endif /* PETTYCOIN_SHADOUBLE_H */
