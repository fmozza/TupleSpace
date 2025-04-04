#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include "tuple_encrypt.h"

void encrypt_generate_nonce(unsigned char *nonce, size_t len)
{
    if (len != 12)
        return;
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f)
    {
        perror("Failed to open /dev/urandom");
        return;
    }
    if (fread(nonce, 1, len, f) != len)
    {
        perror("Failed to read random bytes");
    }
    fclose(f);
}

int encrypt_tuple_encrypt(const unsigned char *plaintext, size_t plaintext_len,
                          const unsigned char *key, const unsigned char *nonce,
                          unsigned char *ciphertext, int *ciphertext_len)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return -1;

    if (EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, key, nonce) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    int len_temp;
    if (EVP_EncryptUpdate(ctx, ciphertext, &len_temp, plaintext, plaintext_len) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    *ciphertext_len = len_temp;

    if (EVP_EncryptFinal_ex(ctx, ciphertext + *ciphertext_len, &len_temp) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    *ciphertext_len += len_temp;

    unsigned char tag[16];
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    memcpy(ciphertext + *ciphertext_len, tag, 16);
    *ciphertext_len += 16;

    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

int encrypt_tuple_decrypt(const unsigned char *ciphertext, size_t ciphertext_len,
                          const unsigned char *key, const unsigned char *nonce,
                          unsigned char *plaintext, int *plaintext_len)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return -1;

    if (EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, key, nonce) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    size_t cipher_len = ciphertext_len - 16;
    unsigned char *tag = (unsigned char *)ciphertext + cipher_len;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, tag) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    int len_temp;
    if (EVP_DecryptUpdate(ctx, plaintext, &len_temp, ciphertext, cipher_len) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    *plaintext_len = len_temp;

    if (EVP_DecryptFinal_ex(ctx, plaintext + *plaintext_len, &len_temp) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    *plaintext_len += len_temp;

    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

int encrypt_derive_session_key(EVP_PKEY *server_key, EVP_PKEY *client_key, unsigned char *session_key)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(server_key, NULL);
    if (!ctx)
        return -1;
    if (EVP_PKEY_derive_init(ctx) <= 0 || EVP_PKEY_derive_set_peer(ctx, client_key) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }
    size_t keylen = 32;
    unsigned char shared_secret[32];
    if (EVP_PKEY_derive(ctx, shared_secret, &keylen) <= 0 || keylen != 32)
    {
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }
    EVP_PKEY_CTX_free(ctx);

    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    if (!md_ctx || EVP_DigestInit_ex(md_ctx, EVP_sha256(), NULL) != 1 ||
        EVP_DigestUpdate(md_ctx, shared_secret, 32) != 1 ||
        EVP_DigestFinal_ex(md_ctx, session_key, NULL) != 1)
    {
        EVP_MD_CTX_free(md_ctx);
        return -1;
    }
    EVP_MD_CTX_free(md_ctx);
    return 0;
}

int encrypt_encrypt_message(const unsigned char *session_key, const unsigned char *nonce,
                            const uint8_t *plaintext, size_t plaintext_len,
                            uint8_t **ciphertext, size_t *ciphertext_len)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        fprintf(stderr, "EVP_CIPHER_CTX_new failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        return -1;
    }
    if (EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, session_key, nonce) != 1)
    {
        fprintf(stderr, "Encrypt init failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    *ciphertext = malloc(plaintext_len + 16); // Data + tag
    if (!*ciphertext)
    {
        fprintf(stderr, "Failed to allocate ciphertext\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    int len;
    *ciphertext_len = 0;

    printf("Encrypting: plaintext_len=%zu, first 8 bytes=%02x%02x%02x%02x%02x%02x%02x%02x\n",
           plaintext_len, plaintext[0], plaintext[1], plaintext[2], plaintext[3],
           plaintext[4], plaintext[5], plaintext[6], plaintext[7]);

    if (EVP_EncryptUpdate(ctx, *ciphertext, &len, plaintext, plaintext_len) != 1)
    {
        fprintf(stderr, "Encrypt update failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        free(*ciphertext);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    *ciphertext_len += len;

    if (EVP_EncryptFinal_ex(ctx, *ciphertext + *ciphertext_len, &len) != 1)
    {
        fprintf(stderr, "Encrypt final failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        free(*ciphertext);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    *ciphertext_len += len;

    unsigned char tag[16];
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag) != 1)
    {
        fprintf(stderr, "Failed to get tag: %s\n", ERR_error_string(ERR_get_error(), NULL));
        free(*ciphertext);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    memcpy(*ciphertext + *ciphertext_len, tag, 16);
    *ciphertext_len += 16;

    printf("Encrypted: ciphertext_len=%zu, tag=%02x%02x%02x%02x...\n",
           *ciphertext_len - 16, tag[0], tag[1], tag[2], tag[3]);

    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

int encrypt_decrypt_message(const unsigned char *session_key, const unsigned char *nonce,
                            const unsigned char *ciphertext, size_t ciphertext_len,
                            uint8_t **plaintext, size_t *plaintext_len)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        fprintf(stderr, "EVP_CIPHER_CTX_new failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        return -1;
    }
    if (EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, session_key, nonce) != 1)
    {
        fprintf(stderr, "Decrypt init failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    size_t cipher_len = ciphertext_len - 16;
    unsigned char *tag = (unsigned char *)ciphertext + cipher_len;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, tag) != 1)
    {
        fprintf(stderr, "Failed to set tag: %s\n", ERR_error_string(ERR_get_error(), NULL));
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    printf("Decrypting: cipher_len=%zu, tag=%02x%02x%02x%02x...\n",
           cipher_len, tag[0], tag[1], tag[2], tag[3]);

    *plaintext = malloc(cipher_len);
    if (!*plaintext)
    {
        fprintf(stderr, "Failed to allocate plaintext\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    int len;
    *plaintext_len = 0;
    printf("Ciphertext first 8 bytes: %02x%02x%02x%02x%02x%02x%02x%02x\n",
           ciphertext[0], ciphertext[1], ciphertext[2], ciphertext[3],
           ciphertext[4], ciphertext[5], ciphertext[6], ciphertext[7]);

    if (EVP_DecryptUpdate(ctx, *plaintext, &len, ciphertext, cipher_len) != 1)
    {
        fprintf(stderr, "Decrypt update failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        free(*plaintext);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    *plaintext_len += len;

    if (EVP_DecryptFinal_ex(ctx, *plaintext + *plaintext_len, &len) != 1)
    {
        fprintf(stderr, "Decrypt final failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        free(*plaintext);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    *plaintext_len += len;

    printf("Decrypted plaintext length: %zu, first 8 bytes: %02x%02x%02x%02x%02x%02x%02x%02x\n",
           *plaintext_len, (*plaintext)[0], (*plaintext)[1], (*plaintext)[2], (*plaintext)[3],
           (*plaintext)[4], (*plaintext)[5], (*plaintext)[6], (*plaintext)[7]);

    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

void encrypt_generate_key_pair(const char *filename)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    if (!ctx)
    {
        perror("Failed to create X25519 context");
        exit(1);
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0)
    {
        perror("Failed to init keygen");
        EVP_PKEY_CTX_free(ctx);
        exit(1);
    }

    EVP_PKEY *key_pair = NULL;
    if (EVP_PKEY_keygen(ctx, &key_pair) <= 0)
    {
        perror("Failed to generate X25519 key pair");
        EVP_PKEY_CTX_free(ctx);
        exit(1);
    }
    EVP_PKEY_CTX_free(ctx);

    FILE *key_file = fopen(filename, "w");
    if (!key_file)
    {
        perror("Failed to open key file for writing");
        EVP_PKEY_free(key_pair);
        exit(1);
    }

    if (PEM_write_PrivateKey(key_file, key_pair, NULL, NULL, 0, NULL, NULL) != 1)
    {
        perror("Failed to write key to PEM");
        fclose(key_file);
        EVP_PKEY_free(key_pair);
        exit(1);
    }

    fclose(key_file);
    EVP_PKEY_free(key_pair);
    printf("Generated key pair saved to %s\n", filename);
}