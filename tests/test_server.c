#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <openssl/rand.h>
#include "network.h"
#include "crypto.h"

int main()
{
    EVP_PKEY *server_key = load_private_key("keys/server_01_key.pem");
    if (!server_key)
        return 1;

    unsigned char server_pub[32];
    size_t pub_len = 32;
    if (get_public_key(server_key, server_pub, &pub_len) < 0)
        return 1;

    int server_fd = setup_server_socket();
    if (server_fd < 0)
        return 1;

    int client_fd = accept_client(server_fd);
    if (client_fd < 0)
    {
        close(server_fd);
        return 1;
    }

    unsigned char client_pub[32];
    if (receive_public_key(client_fd, client_pub, 32) < 0)
    {
        close(client_fd);
        close(server_fd);
        return 1;
    }
    EVP_PKEY *client_key = create_public_key(client_pub, 32);
    if (!client_key)
    {
        close(client_fd);
        close(server_fd);
        return 1;
    }

    if (send_public_key(client_fd, server_pub, pub_len) < 0)
    {
        close(client_fd);
        close(server_fd);
        return 1;
    }

    unsigned char session_key[KEY_LEN];
    if (derive_session_key(server_key, client_key, session_key) < 0)
    {
        close(client_fd);
        close(server_fd);
        return 1;
    }
    printf("Server session key: ");
    for (int i = 0; i < 8; i++)
        printf("%02x", session_key[i]);
    printf("...\n");

    unsigned char *msg;
    uint32_t msg_len;
    if (receive_message(client_fd, &msg, &msg_len) < 0)
    {
        close(client_fd);
        close(server_fd);
        return 1;
    }

    unsigned char *nonce = msg;
    unsigned char *ciphertext = msg + NONCE_LEN;
    size_t cipher_len = msg_len - NONCE_LEN;

    unsigned char *plaintext;
    int plaintext_len;
    if (decrypt_message(session_key, nonce, ciphertext, cipher_len, &plaintext, &plaintext_len) < 0)
    {
        free(msg);
        close(client_fd);
        close(server_fd);
        return 1;
    }
    printf("Server decrypted: %.*s\n", plaintext_len, plaintext);

    const char *response = "Hello from server";
    unsigned char nonce_out[NONCE_LEN];
    if (RAND_bytes(nonce_out, NONCE_LEN) != 1)
    {
        perror("nonce");
        free(msg);
        free(plaintext);
        close(client_fd);
        close(server_fd);
        return 1;
    }
    unsigned char *resp_cipher;
    int resp_cipher_len;
    if (encrypt_message(session_key, nonce_out, response, strlen(response), &resp_cipher, &resp_cipher_len) < 0)
    {
        free(msg);
        free(plaintext);
        close(client_fd);
        close(server_fd);
        return 1;
    }
    printf("Prepared response, ciphertext length: %d\n", resp_cipher_len);

    if (send_message(client_fd, nonce_out, resp_cipher, resp_cipher_len) < 0)
    {
        free(msg);
        free(plaintext);
        free(resp_cipher);
        close(client_fd);
        close(server_fd);
        return 1;
    }

    free(msg);
    free(plaintext);
    free(resp_cipher);
    // Removed: usleep(1000);
    shutdown(client_fd, SHUT_RDWR);
    close(client_fd);
    shutdown(server_fd, SHUT_RDWR);
    close(server_fd);
    EVP_PKEY_free(server_key);
    EVP_PKEY_free(client_key);
    return 0;
}