#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "rsa.h"

int main(int argc, char **argv)
{
	int i, success = 0, error = 0;
	char buf[BUF_SIZE];
	char enc[BLOCK_SIZE];
	char dec[BUF_SIZE];
	struct pvt_key pvt;
	struct pub_key pub;

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

	fcp_gen_keys(&pvt, &pub);

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

	/*
	   mpz_import(M, (BLOCK_SIZE), 1, sizeof(buf[0]), 0, 0, buf);
	   printf("original is [%s]\n", mpz_get_str(NULL, 16, M)); 
	   */

	for(i = 0; i < 100000; i++) {
		int j;

		memset(enc, 0, BLOCK_SIZE);
		memset(dec, 0, BLOCK_SIZE);

		memset(buf, 0, BUF_SIZE);
		for(j = 0; j < BUF_SIZE; j++)
			buf[j] = rand() & 0xFF;

		fcp_encrypt(enc, buf, BUF_SIZE, pub);

		fcp_decrypt(dec, enc, BLOCK_SIZE, pvt);

		if(memcmp(dec, buf, BUF_SIZE) == 0)
			success++;
		else {
			error++;

			printf("Org: ");
			print_hex(buf, BUF_SIZE);
			printf("\n");

			printf("Enc: ");
			print_hex(enc, BLOCK_SIZE);
			printf("\n");

			printf("Dec: ");
			print_hex(dec, BUF_SIZE);
			printf("\n");
			printf("\n");
		}
	}

	printf("\n");
	printf("Tested: %d, Success: %d, Error: %d\n", i, success, error);
	printf("Failrate: %.04f\n", (float)error / (float)i);

	return 0;
}

