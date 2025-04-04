// crypto.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/params.h>
#include "crypto.h"

EVP_PKEY *load_private_key(const char *filename)
{
    FILE *fp = fopen(filename, "r");
    if (!fp)
    {
        perror("fopen key");
        return NULL;
    }
    EVP_PKEY *key = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    if (!key)
    {
        perror("PEM_read_PrivateKey");
        return NULL;
    }
    return key;
}

int get_public_key(EVP_PKEY *key, unsigned char *pub_key, size_t *pub_len)
{
    if (EVP_PKEY_get_raw_public_key(key, pub_key, pub_len) != 1)
    {
        perror("get pubkey");
        return -1;
    }
    return 0;
}

EVP_PKEY *create_public_key(unsigned char *pub_key, size_t pub_len)
{
    EVP_PKEY *key = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, pub_key, pub_len);
    if (!key)
    {
        perror("create pub key");
        return NULL;
    }
    return key;
}

int derive_session_key(EVP_PKEY *priv_key, EVP_PKEY *peer_key, unsigned char *session_key)
{
    unsigned char shared_secret[32];
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(priv_key, NULL);
    if (!ctx || EVP_PKEY_derive_init(ctx) <= 0 || EVP_PKEY_derive_set_peer(ctx, peer_key) <= 0)
    {
        perror("derive init");
        return -1;
    }
    size_t secret_len = 32;
    if (EVP_PKEY_derive(ctx, shared_secret, &secret_len) <= 0)
    {
        perror("derive");
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }
    EVP_PKEY_CTX_free(ctx);

    unsigned char server_pub[32];
    size_t pub_len = 32;
    if (EVP_PKEY_get_raw_public_key(priv_key, server_pub, &pub_len) != 1)
    {
        perror("get server pub");
        return -1;
    }

    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    EVP_KDF_CTX *kdf_ctx = EVP_KDF_CTX_new(kdf);
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string("mode", "EXTRACT_AND_EXPAND", 0),
        OSSL_PARAM_construct_utf8_string("digest", "SHA256", 0),
        OSSL_PARAM_construct_octet_string("key", shared_secret, 32),
        OSSL_PARAM_construct_octet_string("salt", server_pub, 32),
        OSSL_PARAM_construct_octet_string("info", (unsigned char *)"test_server", 11),
        OSSL_PARAM_construct_end()};
    if (!kdf_ctx || EVP_KDF_derive(kdf_ctx, session_key, KEY_LEN, params) <= 0)
    {
        perror("hkdf");
        fprintf(stderr, "OpenSSL error: %s\n", ERR_error_string(ERR_get_error(), NULL));
        EVP_KDF_CTX_free(kdf_ctx);
        EVP_KDF_free(kdf);
        return -1;
    }
    EVP_KDF_CTX_free(kdf_ctx);
    EVP_KDF_free(kdf);
    return 0;
}

int decrypt_message(unsigned char *session_key, unsigned char *nonce, unsigned char *ciphertext, size_t cipher_len, unsigned char **plaintext, int *plaintext_len)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx || EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, session_key, nonce) != 1)
    {
        perror("decrypt init");
        return -1;
    }
    unsigned char tag[16];
    memcpy(tag, ciphertext + (cipher_len - 16), 16);
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, tag) != 1)
    {
        perror("set tag");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    *plaintext = malloc(cipher_len - 16);
    int len;
    if (EVP_DecryptUpdate(ctx, *plaintext, &len, ciphertext, cipher_len - 16) != 1)
    {
        perror("decrypt update");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    *plaintext_len = len;
    if (EVP_DecryptFinal_ex(ctx, *plaintext + len, &len) != 1)
    {
        perror("decrypt final");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    *plaintext_len += len;
    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

int encrypt_message(unsigned char *session_key, unsigned char *nonce, const char *message, size_t msg_len, unsigned char **ciphertext, int *cipher_len)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx || EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, session_key, nonce) != 1)
    {
        perror("encrypt init");
        return -1;
    }
    *ciphertext = malloc(msg_len + 16);
    int len;
    if (EVP_EncryptUpdate(ctx, *ciphertext, &len, (unsigned char *)message, msg_len) != 1)
    {
        perror("encrypt update");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    *cipher_len = len;
    if (EVP_EncryptFinal_ex(ctx, *ciphertext + len, &len) != 1)
    {
        perror("encrypt final");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    *cipher_len += len;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, *ciphertext + *cipher_len) != 1)
    {
        perror("get tag");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    *cipher_len += 16;
    EVP_CIPHER_CTX_free(ctx);
    return 0;
}