#ifndef NETWORK_H
#define NETWORK_H

#include <stdint.h>

#define PORT 12345
#define NONCE_LEN 12  // For ChaCha20Poly1305
#define SPACE_ID_LEN 32  // Unused now, kept for future

int setup_server_socket();
int accept_client(int server_fd);
int send_public_key(int client_fd, unsigned char* pub_key, size_t pub_len);
int receive_public_key(int client_fd, unsigned char* pub_key, size_t pub_len);
int receive_message(int client_fd, unsigned char** msg, uint32_t* msg_len);
int send_message(int client_fd, unsigned char* nonce, unsigned char* ciphertext, int cipher_len);

#endif