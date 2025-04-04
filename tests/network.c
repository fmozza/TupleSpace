#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/time.h>
#include "network.h"

int setup_server_socket()
{
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0)
    {
        perror("socket");
        return -1;
    }

    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0)
    {
        perror("setsockopt SO_REUSEADDR");
        return -1;
    }

    struct sockaddr_in addr = {AF_INET, htons(PORT), {INADDR_ANY}, {0}};
    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        perror("bind");
        return -1;
    }
    if (listen(server_fd, 1) < 0)
    {
        perror("listen");
        return -1;
    }
    printf("Server listening on port %d...\n", PORT);
    return server_fd;
}

int accept_client(int server_fd)
{
    int client_fd = accept(server_fd, NULL, NULL);
    if (client_fd < 0)
    {
        perror("accept");
        return -1;
    }
    int flag = 1;
    if (setsockopt(client_fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(int)) < 0)
    {
        perror("setsockopt TCP_NODELAY");
        return -1;
    }
    return client_fd;
}

int send_public_key(int client_fd, unsigned char *pub_key, size_t pub_len)
{
    ssize_t bytes_written = write(client_fd, pub_key, pub_len);
    if (bytes_written != pub_len)
    {
        perror("write server pub");
        printf("Wrote %zd/%zu bytes\n", bytes_written, pub_len);
        return -1;
    }
    printf("Sent public key: %zd bytes\n", bytes_written);
    return 0;
}

int receive_public_key(int client_fd, unsigned char *pub_key, size_t pub_len)
{
    ssize_t bytes_read = read(client_fd, pub_key, pub_len);
    if (bytes_read != pub_len)
    {
        perror("read client pub");
        printf("Read %zd/%zu bytes\n", bytes_read, pub_len);
        return -1;
    }
    printf("Received public key: %zd bytes\n", bytes_read);
    return 0;
}

int receive_message(int client_fd, unsigned char **msg, uint32_t *msg_len)
{
    uint32_t total_len;
    ssize_t bytes_read = read(client_fd, &total_len, sizeof(total_len));
    if (bytes_read != sizeof(total_len))
    {
        perror("read msg len");
        printf("Read %zd/%zu bytes for length\n", bytes_read, sizeof(total_len));
        return -1;
    }
    total_len = ntohl(total_len);
    printf("Received total message length (including prefix): %u\n", total_len);

    if (total_len < 4)
    {
        printf("Invalid length: %u\n", total_len);
        return -1;
    }
    *msg_len = total_len - 4;
    printf("Payload length to read: %u\n", *msg_len);

    *msg = malloc(*msg_len);
    if (!*msg)
    {
        perror("malloc msg");
        return -1;
    }

    size_t total_read = 0;
    while (total_read < *msg_len)
    {
        bytes_read = read(client_fd, *msg + total_read, *msg_len - total_read);
        if (bytes_read < 0)
        {
            perror("read msg");
            printf("Bytes read: %zd, total %zu/%u\n", bytes_read, total_read, *msg_len);
            free(*msg);
            return -1;
        }
        if (bytes_read == 0)
        {
            printf("Connection closed by client: expected %u, got %zu\n", *msg_len, total_read);
            free(*msg);
            return -1;
        }
        total_read += bytes_read;
        printf("Read %zd bytes, total %zu/%u, raw: ", bytes_read, total_read, *msg_len);
        for (size_t i = total_read - bytes_read; i < total_read; i++)
        {
            printf("%02x", (*msg)[i]);
        }
        printf("\n");
    }
    printf("Message read successfully, %zu bytes\n", total_read);
    return 0;
}

int send_message(int client_fd, unsigned char *nonce, unsigned char *ciphertext, int cipher_len)
{
    uint32_t total_len = htonl(4 + NONCE_LEN + cipher_len); // Fixed: Include nonce length
    ssize_t bytes_written = write(client_fd, &total_len, 4);
    if (bytes_written != 4)
    {
        perror("write total len");
        printf("Wrote %zd/4 bytes\n", bytes_written);
        return -1;
    }
    printf("Sent length: %zd bytes\n", bytes_written);

    bytes_written = write(client_fd, nonce, NONCE_LEN);
    if (bytes_written != NONCE_LEN)
    {
        perror("write nonce");
        printf("Wrote %zd/%d bytes\n", bytes_written, NONCE_LEN);
        return -1;
    }
    printf("Sent nonce: %zd bytes\n", bytes_written);

    bytes_written = write(client_fd, ciphertext, cipher_len);
    if (bytes_written != cipher_len)
    {
        perror("write ciphertext");
        printf("Wrote %zd/%d bytes\n", bytes_written, cipher_len);
        return -1;
    }
    printf("Sent message: %zd bytes\n", bytes_written);
    printf("Response sent successfully\n");
    return 0;
}