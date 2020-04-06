#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "rsa.h"

int main(int argc, char **argv)
{
	int i;
	struct pvt_key pvt;
	struct pub_key pub;
	char buf[BUF_SIZE];
	int len = BUF_SIZE;
	char *enc;
	int enc_len;	
	char *dec;
	int dec_len;

	srand(time(NULL));

	/* Initialize public key */
	mpz_init(pub.n);
	mpz_init(pub.e); 

	/* Initialize private key */
	mpz_init(pvt.n); 
	mpz_init(pvt.e); 
	mpz_init(pvt.d); 
	mpz_init(pvt.p); 
	mpz_init(pvt.q); 

	/* Generate the private and public keys */
	gen_keys(&pvt, &pub);

	printf("---------------Private Key------------------\n");
	printf("pvt.n: %s\n", mpz_get_str(NULL, 16, pvt.n));
	printf("pvt.e: %s\n", mpz_get_str(NULL, 16, pvt.e));
	printf("pvt.d: %s\n", mpz_get_str(NULL, 16, pvt.d));
	printf("pvt.p: %s\n", mpz_get_str(NULL, 16, pvt.p));
	printf("pvt.q: %s\n", mpz_get_str(NULL, 16, pvt.q));

	printf("---------------Public Key-----------------\n");
	printf("pub.n: %s\n", mpz_get_str(NULL, 16, pub.n));
	printf("pub.e: %s\n", mpz_get_str(NULL, 16, pub.e));
	printf("\n");

	memset(buf, 0, len);
	for(i = 0; i < len; i++)
		buf[i] = rand() & 0xFF;

	printf("Original: ");
	print_hex(buf, len);
	printf("\n");

	if(encrypt(&enc, &enc_len, buf, len, pub) < 0) {
		printf("Failed to encrypt\n");
		goto err_free_keys;
	}

	printf("Encrypted: ");
	print_hex(enc, enc_len);
	printf("\n");

	if(decrypt(&dec, &dec_len, enc, enc_len, pvt) < 0) {
		printf("Failed to decrypt\n");
		goto err_free_enc;
	}

	printf("Decrypted: ");
	print_hex(dec, dec_len);
	printf("\n");

	free(dec);

err_free_enc:
	free(enc);

err_free_keys:
	free_keys(&pvt, &pub);

	return 0;
}

