#pragma once
#include "keys.h"
#include <gmp.h>

extern mpz_t q;   // "small" prime; should be 256 bits or more
extern mpz_t p;   // "large" prime; should be 2048 bits or more, with q|(p-1)
extern mpz_t g;   // generator of the subgroup of order q
extern size_t qBitlen;   // length of q in bits
extern size_t pBitlen;   // length of p in bits
extern size_t qLen;   // length of q in bytes
extern size_t pLen;   // length of p in bytes

extern const char* hmacsalt; // Arbitrary HMAC salt

#ifdef __cplusplus
extern "C" {
#endif

int init(const char* fname);
int initFromScratch(size_t qBitlen, size_t pBitlen);
int dhGen(mpz_t sk, mpz_t pk);
int dhGenk(dhKey* k);
int dhFinal(mpz_t sk_mine, mpz_t pk_mine, mpz_t pk_yours, unsigned char* keybuf, size_t buflen);
int dh3Final(mpz_t a, mpz_t A, mpz_t x, mpz_t X, mpz_t B, mpz_t Y, unsigned char* keybuf, size_t buflen);
int dh3Finalk(dhKey* skA, dhKey* skX, dhKey* pkB, dhKey* pkY, unsigned char* keybuf, size_t buflen);
int encrypt_message(unsigned char* plaintext, int plaintext_len, unsigned char* ciphertext, unsigned char* key);
int decrypt_message(unsigned char* ciphertext, int ciphertext_len, unsigned char* plaintext, unsigned char* key);
int sendKey(int sock, dhKey* key);
int receiveKey(int sock, dhKey* key);

#ifdef __cplusplus
}
#endif





