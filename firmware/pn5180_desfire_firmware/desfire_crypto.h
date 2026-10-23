#ifndef DESFIRE_CRYPTO_H
#define DESFIRE_CRYPTO_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// AES-128 CBC Encrypt / Decrypt
void aes128_cbc_encrypt(const uint8_t *key16, uint8_t *iv16, const uint8_t *in, uint8_t *out, size_t len);
void aes128_cbc_decrypt(const uint8_t *key16, uint8_t *iv16, const uint8_t *in, uint8_t *out, size_t len);

// 2-Key Triple DES (EDE / DED) CBC Encrypt / Decrypt
// key16: 16 bayt (K1 8 bayt, K2 8 bayt). Single DES ise K1 == K2 verilir.
void des3_2key_cbc_encrypt(const uint8_t *key16, uint8_t *iv8, const uint8_t *in, uint8_t *out, size_t len);
void des3_2key_cbc_decrypt(const uint8_t *key16, uint8_t *iv8, const uint8_t *in, uint8_t *out, size_t len);

#ifdef __cplusplus
}
#endif

#endif // DESFIRE_CRYPTO_H
