#include "protocol.h"
#include "shadouble.h"

/* Double SHA256, as per bitcoin */
void SHA256_Double_Final(SHA256_CTX *ctx,
			 struct protocol_double_sha *sha)
{
	SHA256_Final(sha->sha, ctx);
	SHA256_Init(ctx);
	SHA256_Update(ctx, sha->sha, SHA256_DIGEST_LENGTH);
	SHA256_Final(sha->sha, ctx);
}
