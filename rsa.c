#include "rsa.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <math.h>

void print_hex(char* arr, int len)
{
	int i;
	for(i = 0; i < len; i++)
		printf("%02x", (unsigned char) arr[i]); 
}

/* NOTE: Assumes mpz_t's are initted in ku and kp */
void gen_keys(struct pvt_key *pvt, struct pub_key *pub)
{
	char buf[BUFFER_SIZE];
	int i;
	mpz_t phi;
	mpz_t tmp1;
	mpz_t tmp2;

	mpz_init(phi);
	mpz_init(tmp1);
	mpz_init(tmp2);

	srand(time(NULL));

	/* 
	 * Insetead of selecting e st. gcd(phi, e) = 1; 1 < e < phi, lets choose e
	 * first then pick p,q st. gcd(e, p-1) = gcd(e, q-1) = 1
	 * We'll set e globally.  I've seen suggestions to use primes like 3, 17 or 
	 * 65537, as they make coming calculations faster.  Lets use 3.
	 */
	mpz_set_ui(pvt->e, 3); 

	/* Select p and q */
	/* Start with p */
	/* Set the bits of tmp randomly */
	for(i = 0; i < BUFFER_SIZE; i++)
		buf[i] = rand() % 0xFF;

	/* Set the top two bits to 1 to ensure int(tmp) is relatively large */
	buf[0] |= 0xC0;

	/* Set the bottom bit to 1 to ensure int(tmp) is odd (better for finding primes) */
	buf[BUFFER_SIZE - 1] |= 0x01;

	/* Interpret this char buffer as an int */
	mpz_import(tmp1, BUFFER_SIZE, 1, sizeof(buf[0]), 0, 0, buf);

	/* Pick the next prime starting from that random number */
	mpz_nextprime(pvt->p, tmp1);

	/* Make sure this is a good choice */
	mpz_mod(tmp2, pvt->p, pvt->e);        /* If p mod e == 1, gcd(phi, e) != 1 */
	while(!mpz_cmp_ui(tmp2, 1)) {
		mpz_nextprime(pvt->p, pvt->p);
		mpz_mod(tmp2, pvt->p, pvt->e);
	}

	/* Now select q */
	do {
		for(i = 0; i < BUFFER_SIZE; i++)
			buf[i] = rand() % 0xFF;

		/* Set the top two bits to 1 to ensure int(tmp) is relatively large */
		buf[0] |= 0xC0;
		/* Set the bottom bit to 1 to ensure int(tmp) is odd */
		buf[BUFFER_SIZE - 1] |= 0x01;
		/* Interpret this char buffer as an int */
		mpz_import(tmp1, (BUFFER_SIZE), 1, sizeof(buf[0]), 0, 0, buf);
		/* Pick the next prime starting from that random number */
		mpz_nextprime(pvt->q, tmp1);
		mpz_mod(tmp2, pvt->q, pvt->e);
		while(!mpz_cmp_ui(tmp2, 1)) {
			mpz_nextprime(pvt->q, pvt->q);
			mpz_mod(tmp2, pvt->q, pvt->e);
		}
	} while(mpz_cmp(pvt->p, pvt->q) == 0); /* If we have identical primes (unlikely), try again */

	/* Calculate n = p x q */
	mpz_mul(pvt->n, pvt->p, pvt->q);

	/* Compute phi(n) = (p-1)(q-1) */
	mpz_sub_ui(tmp1, pvt->p, 1);
	mpz_sub_ui(tmp2, pvt->q, 1);
	mpz_mul(phi, tmp1, tmp2);

	/* Calculate d (multiplicative inverse of e mod phi) */
	if(mpz_invert(pvt->d, pvt->e, phi) == 0) {
		mpz_gcd(tmp1, pvt->e, phi);
		printf("gcd(e, phi) = [%s]\n", mpz_get_str(NULL, 16, tmp1));
		printf("Invert failed\n");
	}

	/* Set public key */
	mpz_set(pub->e, pvt->e);
	mpz_set(pub->n, pvt->n);
}

void free_keys(struct pvt_key *pvt, struct pub_key *pub)
{
	if(pvt != NULL) {
		mpz_clear(pvt->n);
		mpz_clear(pvt->e);
		mpz_clear(pvt->d);
		mpz_clear(pvt->p);
		mpz_clear(pvt->q);
	}

	if(pub != NULL) {
		mpz_clear(pub->n);
		mpz_clear(pub->e);
	}
}

void block_encrypt(mpz_t C, mpz_t M, struct pub_key pub)
{
	/* C = M^e mod n */
	mpz_powm(C, M, pub.e, pub.n);
}

int encrypt(char **out, int *out_len, char *in, int len, struct pub_key pub)
{
	char *ret;
	char block[BLOCK_SIZE];
	mpz_t m;
	mpz_t c;

	int i = 0;
	int left = len;
	int num = (int)ceil((double)len / BUF_SIZE);
	int size = num * BLOCK_SIZE;

	ret = malloc(size);
	if(ret == NULL)
		return -1;

	memset(ret, 0, size);

	mpz_init(m);
	mpz_init(c);

	while(left > 0) {
		int from = len - left;
		int to = (i + 1) * BLOCK_SIZE;
		int sz = (left > BUF_SIZE) ? (BUF_SIZE) : (left);
		int off = BLOCK_SIZE - sz;
		size_t enc_len = 0;

		memset(block, 0, BLOCK_SIZE);
		block[0] = 0x01;
		block[1] = 0x02;
		memcpy(block + off, in + from, sz);

		/* Convert bytestream to integer  */
		mpz_import(m, BLOCK_SIZE, 1, sizeof(block[0]), 0, 0, block);

		/* Perform encryption on that block */
		block_encrypt(c, m, pub);
	
		memset(block, 0, BLOCK_SIZE);

		/* Pull out bytestream of ciphertext */
		mpz_export(block, &enc_len, 1, sizeof(char), 0, 0, c);

		memcpy(ret + to - enc_len, block, enc_len);

		left -= sz;
		i++;
	}

	*out = ret;
	*out_len = size;

	mpz_clear(m);
	mpz_clear(c);

	return 0;
} 

void block_decrypt(mpz_t M, mpz_t C, struct pvt_key pvt)
{
	mpz_powm(M, C, pvt.d, pvt.n);
}

int decrypt(char **out, int *out_len, char *in, int len, struct pvt_key pvt)
{
	int i;
	int num = len / BLOCK_SIZE;
	int msg_idx = 0;
	char block[BLOCK_SIZE];
	int size = num * BUF_SIZE;
	char *ret;
	mpz_t c;
	mpz_t m;

	ret = malloc(size);
	if(ret == NULL)
		return -1;

	memset(ret, 0, size);

	mpz_init(c);
	mpz_init(m);

	for(i = 0; i < num; i++) {
		/* Pull block into mpz_t */
		mpz_import(c, BLOCK_SIZE, 1, sizeof(char), 0, 0, 
				in + (i * BLOCK_SIZE));

		/* Decrypt block */
		block_decrypt(m, c, pvt);

		/* Convert back to bitstream */
		mpz_export(block, NULL, 1, sizeof(char), 0, 0, m);

		/* Copy over the message part of the plaintext to the message return var */
		memcpy(ret + (i * BUF_SIZE), block + 2, BUF_SIZE);
	}

	*out = ret;
	*out_len = size;

	mpz_clear(m);
	mpz_clear(c);

	return msg_idx;
}
