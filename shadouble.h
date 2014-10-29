#ifndef PETTYCOIN_SHADOUBLE_H
#define PETTYCOIN_SHADOUBLE_H
#include "config.h"
#include <openssl/sha.h>

struct protocol_double_sha;
#define double_sha(shap, p) double_sha_of((shap), (p), sizeof(*p))
#define double_sha_arr(shap, p, n) double_sha_of((shap), (p), sizeof(*p)*(n))

void double_sha_of(struct protocol_double_sha *sha, const void *p, size_t len);

/* Checks data is defined, if using valgrind */
int SHA256_CheckUpdate(SHA256_CTX *c, const void *data, size_t len);

void SHA256_Double_Final(SHA256_CTX *ctx, struct protocol_double_sha *sha);
#endif /* PETTYCOIN_SHADOUBLE_H */
