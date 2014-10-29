#include "protocol.h"
#include "shadouble.h"
#include "valgrind.h"

int SHA256_CheckUpdate(SHA256_CTX *c, const void *data, size_t len)
{
	return SHA256_Update(c, check_mem(data, len), len);
}

/* Double SHA256, as per bitcoin */
void SHA256_Double_Final(SHA256_CTX *ctx,
			 struct protocol_double_sha *sha)
{
	SHA256_Final(sha->sha, ctx);
	SHA256_Init(ctx);
	SHA256_CheckUpdate(ctx, sha->sha, SHA256_DIGEST_LENGTH);
	SHA256_Final(sha->sha, ctx);
}

void double_sha_of(struct protocol_double_sha *sha, const void *p, size_t len)
{
	SHA256_CTX sha256;

	SHA256_Init(&sha256);
	SHA256_CheckUpdate(&sha256, p, len);
	SHA256_Double_Final(&sha256, sha);
}
