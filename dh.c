#include "dh.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "util.h"
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <sys/socket.h>  // For send and recv functions

mpz_t q, p, g;
size_t qBitlen, pBitlen, qLen, pLen;

const char* hmacsalt = "example-salt"; // Arbitrary HMAC salt

int init(const char* fname)
{
    mpz_init(q);
    mpz_init(p);
    mpz_init(g);
    FILE* f = fopen(fname, "rb");
    if (!f) {
        fprintf(stderr, "Could not open file 'params'\n");
        return -1;
    }
    int nvalues = gmp_fscanf(f, "q = %Zd\np = %Zd\ng = %Zd", q, p, g);
    fclose(f);
    if (nvalues != 3) {
        printf("Couldn't parse parameter file\n");
        return -1;
    }
    qBitlen = mpz_sizeinbase(q, 2);
    pBitlen = mpz_sizeinbase(p, 2);
    qLen = qBitlen / 8 + (qBitlen % 8 != 0);
    pLen = pBitlen / 8 + (pBitlen % 8 != 0);
    return 0;
}

int dhGen(mpz_t sk, mpz_t pk)
{
    FILE* f = fopen("/dev/urandom", "rb");
    if (!f) {
        fprintf(stderr, "Failed to open /dev/urandom\n");
        return -1;
    }
    size_t buflen = qLen + 32; // Extra length for uniform distribution
    unsigned char* buf = malloc(buflen);
    fread(buf, 1, buflen, f);
    fclose(f);
    mpz_t a;
    mpz_init(a);
    mpz_import(a, buflen, 1, 1, 1, 0, buf);
    mpz_mod(sk, a, q);
    mpz_powm(pk, g, sk, p);
    mpz_clear(a);
    free(buf);
    return 0;
}

int dhGenk(dhKey* k)
{
    assert(k);
    initKey(k);
    return dhGen(k->SK, k->PK);
}

int dhFinal(mpz_t sk_mine, mpz_t pk_mine, mpz_t pk_yours, unsigned char* keybuf, size_t buflen)
{
    mpz_t s;
    mpz_init(s);
    mpz_powm(s, pk_yours, sk_mine, p);

    unsigned char* shared_secret = malloc(pLen);
    memset(shared_secret, 0, pLen);
    size_t nBytes;
    mpz_export(shared_secret, &nBytes, 1, 1, 1, 0, s);
    unsigned char PRK[EVP_MAX_MD_SIZE];
    unsigned int PRK_len;
    HMAC(EVP_sha256(), hmacsalt, strlen(hmacsalt), shared_secret, nBytes, PRK, &PRK_len);

    EVP_MAC* mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    EVP_MAC_CTX* ctx = EVP_MAC_CTX_new(mac);
    OSSL_PARAM params[2] = { OSSL_PARAM_construct_utf8_string("digest", "SHA256", 6), OSSL_PARAM_construct_end() };

    EVP_MAC_init(ctx, PRK, PRK_len, params);
    EVP_MAC_update(ctx, (unsigned char*)"\0", 1);
    EVP_MAC_final(ctx, keybuf, &buflen, buflen);

    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);
    mpz_clear(s);
    free(shared_secret);
    return 0;
}

int dh3Final(mpz_t a, mpz_t A, mpz_t x, mpz_t X, mpz_t B, mpz_t Y, unsigned char* keybuf, size_t buflen)
{
    mpz_t AY, XY, XB;
    mpz_init(AY);
    mpz_init(XY);
    mpz_init(XB);

    mpz_powm(AY, Y, a, p);
    mpz_powm(XY, Y, x, p);
    mpz_powm(XB, B, x, p);

    if (mpz_cmp(A, B) > 0) {
        mpz_swap(AY, XB);
    }

    unsigned char* shared_secrets = malloc(3 * pLen);
    memset(shared_secrets, 0, 3 * pLen);
    size_t nBytes;
    unsigned char* buf = shared_secrets;
    mpz_export(buf, &nBytes, 1, 1, 1, 0, AY);
    buf += pLen;
    mpz_export(buf, &nBytes, 1, 1, 1, 0, XY);
    buf += pLen;
    mpz_export(buf, &nBytes, 1, 1, 1, 0, XB);

    unsigned char PRK[EVP_MAX_MD_SIZE];
    unsigned int PRK_len;
    HMAC(EVP_sha256(), hmacsalt, strlen(hmacsalt), shared_secrets, 3 * pLen, PRK, &PRK_len);

    EVP_MAC* mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    EVP_MAC_CTX* ctx = EVP_MAC_CTX_new(mac);
    OSSL_PARAM params[2] = { OSSL_PARAM_construct_utf8_string("digest", "SHA256", 6), OSSL_PARAM_construct_end() };

    EVP_MAC_init(ctx, PRK, PRK_len, params);
    EVP_MAC_update(ctx, (unsigned char*)"\0", 1);
    EVP_MAC_final(ctx, keybuf, &buflen, buflen);

    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);
    mpz_clear(AY);
    mpz_clear(XY);
    mpz_clear(XB);
    free(shared_secrets);
    return 0;
}

int dh3Finalk(dhKey* skA, dhKey* skX, dhKey* pkB, dhKey* pkY, unsigned char* keybuf, size_t buflen)
{
    return dh3Final(skA->SK, skA->PK, skX->SK, skX->PK, pkB->PK, pkY->PK, keybuf, buflen);
}

int encrypt_message(unsigned char* plaintext, int plaintext_len, unsigned char* ciphertext, unsigned char* key)
{
    EVP_CIPHER_CTX* ctx;
    int len;
    int ciphertext_len;

    if (!(ctx = EVP_CIPHER_CTX_new())) return -1;
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, key + 16)) return -1;

    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) return -1;
    ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) return -1;
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int decrypt_message(unsigned char* ciphertext, int ciphertext_len, unsigned char* plaintext, unsigned char* key)
{
    EVP_CIPHER_CTX* ctx;
    int len;
    int plaintext_len;

    if (!(ctx = EVP_CIPHER_CTX_new())) return -1;
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, key + 16)) return -1;

    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) return -1;
    plaintext_len = len;

    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) return -1;
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

int sendKey(int sock, dhKey* key)
{
    size_t pk_len;
    unsigned char* pk_buf = Z2BYTES(NULL, &pk_len, key->PK);
    if (send(sock, &pk_len, sizeof(pk_len), 0) == -1) return -1;
    if (send(sock, pk_buf, pk_len, 0) == -1) return -1;
    free(pk_buf);
    return 0;
}

int receiveKey(int sock, dhKey* key)
{
    size_t pk_len;
    if (recv(sock, &pk_len, sizeof(pk_len), 0) == -1) return -1;
    unsigned char* pk_buf = malloc(pk_len);
    if (recv(sock, pk_buf, pk_len, 0) == -1) return -1;
    BYTES2Z(key->PK, pk_buf, pk_len);
    free(pk_buf);
    return 0;
}

