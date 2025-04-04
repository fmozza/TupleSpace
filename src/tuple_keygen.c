#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#define DEFAULT_KEY_DIR "/usr/local/tuple_space/.keys"

void generate_key_pair(const char *filename)
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

int main(int argc, char *argv[])
{
    if (argc != 3)
    {
        fprintf(stderr, "Usage: %s <type> <id>\n", argv[0]);
        fprintf(stderr, "  <type>: 'server' or 'client'\n");
        fprintf(stderr, "  <id>: Unique identifier (e.g., '01', '001')\n");
        fprintf(stderr, "Example: %s server 01\n", argv[0]);
        return 1;
    }

    const char *type = argv[1];
    const char *id = argv[2];
    if (strcmp(type, "server") != 0 && strcmp(type, "client") != 0)
    {
        fprintf(stderr, "Invalid type: must be 'server' or 'client'\n");
        return 1;
    }

    char filename[256];
    snprintf(filename, sizeof(filename), "%s/%s_%s_key.pem", DEFAULT_KEY_DIR, type, id);
    generate_key_pair(filename);
    return 0;
}