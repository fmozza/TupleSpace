// crypto.h
#ifndef CRYPTO_H
#define CRYPTO_H

#include <openssl/evp.h>

#define KEY_LEN 32

EVP_PKEY *load_private_key(const char *filename);
int get_public_key(EVP_PKEY *key, unsigned char *pub_key, size_t *pub_len);
EVP_PKEY *create_public_key(unsigned char *pub_key, size_t pub_len);
int derive_session_key(EVP_PKEY *priv_key, EVP_PKEY *peer_key, unsigned char *session_key);
int decrypt_message(unsigned char *session_key, unsigned char *nonce, unsigned char *ciphertext, size_t cipher_len, unsigned char **plaintext, int *plaintext_len);
int encrypt_message(unsigned char *session_key, unsigned char *nonce, const char *message, size_t msg_len, unsigned char **ciphertext, int *cipher_len);

#endif