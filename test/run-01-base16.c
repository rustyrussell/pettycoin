#include "../base58.c"

int main(void)
{
	/* Address: 1PtcjakvZBeggokcAGb1KbVvMRi3NT6LMk. */
	const char priv_b16[] =
		"4e111544df178877C7e8483e92b7ef1b40cE7dc4e944261f4f32e2ed13340c0A";
	const char priv_b10[] =
		"35310585383039988783548932038956396952442822145226977502125905800903068486666";

	BIGNUM *bn_priv;
	BIGNUM *bn_priv_from_dec = NULL;
	BIGNUM *bn_priv_from_hex = NULL;

	bn_priv = BN_new();
	assert(raw_decode_base_n(bn_priv, priv_b16, strlen(priv_b16), 16));
	assert(BN_dec2bn(&bn_priv_from_dec, priv_b10) == strlen(priv_b10));
	assert(BN_hex2bn(&bn_priv_from_hex, priv_b16) == strlen(priv_b16));

	assert(BN_cmp(bn_priv, bn_priv_from_dec) == 0);
	assert(BN_cmp(bn_priv, bn_priv_from_hex) == 0);

	BN_free(bn_priv_from_hex);
	BN_free(bn_priv_from_dec);
	BN_free(bn_priv);

	return 0;
}
