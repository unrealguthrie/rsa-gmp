#ifndef _RSA_H
#define _RSA_H

#include <gmp.h>

#define MODULUS_SIZE 1024                   /* This is the number of bits we want in the modulus */
#define BLOCK_SIZE (MODULUS_SIZE/8)         /* This is the size of a block that gets en/decrypted at once */
#define BUF_SIZE (BLOCK_SIZE-2)
#define BUFFER_SIZE ((MODULUS_SIZE/8)/2)    /* This is the number of bytes in n and p */

struct pub_key {
    mpz_t n; /* Modulus */
    mpz_t e; /* Public Exponent */
};

struct pvt_key {
    mpz_t n; /* Modulus */
    mpz_t e; /* Public Exponent */
    mpz_t d; /* Private Exponent */
    mpz_t p; /* Starting prime p */
    mpz_t q; /* Starting prime q */
};


void print_hex(char* arr, int len);

void gen_keys(struct pvt_key *pvt, struct pub_key *pub);
void free_keys(struct pvt_key *pvt, struct pub_key *pub);

int encrypt(char **out, int *out_len, char *in, int len, struct pub_key pub);
int decrypt(char **out, int *out_len, char *in, int len, struct pvt_key pvt);

#endif
