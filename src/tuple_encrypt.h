#ifndef TUPLE_ENCRYPT_H
#define TUPLE_ENCRYPT_H

#include <stdint.h>
#include <stddef.h>
#include <openssl/evp.h>

void encrypt_generate_nonce(unsigned char *nonce, size_t len);
int encrypt_tuple_encrypt(const unsigned char *plaintext, size_t plaintext_len,
                          const unsigned char *key, const unsigned char *nonce,
                          unsigned char *ciphertext, int *ciphertext_len);
int encrypt_tuple_decrypt(const unsigned char *ciphertext, size_t ciphertext_len,
                          const unsigned char *key, const unsigned char *nonce,
                          unsigned char *plaintext, int *plaintext_len);
int encrypt_derive_session_key(EVP_PKEY *server_key, EVP_PKEY *client_key, unsigned char *session_key);
int encrypt_encrypt_message(const unsigned char *session_key, const unsigned char *nonce,
                            const uint8_t *plaintext, size_t plaintext_len,
                            uint8_t **ciphertext, size_t *ciphertext_len);
int encrypt_decrypt_message(const unsigned char *session_key, const unsigned char *nonce,
                            const unsigned char *ciphertext, size_t ciphertext_len,
                            uint8_t **plaintext, size_t *plaintext_len);
void encrypt_generate_key_pair(const char *filename);

#endif