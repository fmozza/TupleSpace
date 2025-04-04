#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#include <unistd.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <endian.h>
#include <netinet/tcp.h>
#include <sys/epoll.h>
#include <errno.h>
#include <openssl/evp.h>
#include "tuple_network.h"
#include "tuple_encrypt.h"

int network_init_server(const char *server_id, int *serverfd, int *notifyfd)
{
    *serverfd = socket(AF_INET, SOCK_STREAM, 0);
    if (*serverfd < 0)
    {
        perror("socket failed");
        return -1;
    }
    int opt = 1;
    setsockopt(*serverfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    setsockopt(*serverfd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));

    struct sockaddr_in addr = {AF_INET, htons(SERVER_PORT), {INADDR_ANY}, {0}};
    if (bind(*serverfd, (struct sockaddr *)&addr, sizeof(addr)) < 0 ||
        listen(*serverfd, MAX_CLIENTS) < 0)
    {
        perror("bind/listen failed");
        close(*serverfd);
        return -1;
    }

    *notifyfd = socket(AF_INET, SOCK_STREAM, 0);
    if (*notifyfd < 0)
    {
        perror("notify socket failed");
        close(*serverfd);
        return -1;
    }
    addr.sin_port = htons(NOTIFY_PORT);
    if (bind(*notifyfd, (struct sockaddr *)&addr, sizeof(addr)) < 0 ||
        listen(*notifyfd, MAX_CLIENTS) < 0)
    {
        perror("notify bind/listen failed");
        close(*notifyfd);
        close(*serverfd);
        return -1;
    }

    int s_port = SERVER_PORT;
    int n_port = NOTIFY_PORT;
    printf("Server %s listening on port %d, notifications on %d...\n", server_id, s_port, n_port);
    return 0;
}

int network_handle_client(int clientfd, TupleSpace *space, NotifyArgs *notify_args)
{
    // Read client public key
    unsigned char buffer[32];
    size_t total_read = 0;
    while (total_read < 32)
    {
        ssize_t bytes_read = read(clientfd, buffer + total_read, 32 - total_read);
        if (bytes_read <= 0)
        {
            perror("Failed to read client public key");
            fprintf(stderr, "Bytes read: %zd, total: %zu/32\n", bytes_read, total_read);
            return -1;
        }
        total_read += bytes_read;
        printf("Read %zd bytes, total %zu/32 for client pubkey\n", bytes_read, total_read);
    }
    printf("Received client pubkey: %02x%02x%02x%02x...\n", buffer[0], buffer[1], buffer[2], buffer[3]);

    // Create EVP_PKEY from client public key
    EVP_PKEY *client_key = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, buffer, 32);
    if (!client_key)
    {
        perror("Invalid client public key");
        return -1;
    }

    // Send server public key
    unsigned char server_pubkey[32];
    size_t pubkey_len = 32;
    if (EVP_PKEY_get_raw_public_key(space->server_key, server_pubkey, &pubkey_len) != 1 || pubkey_len != 32)
    {
        perror("Failed to extract server public key");
        EVP_PKEY_free(client_key);
        return -1;
    }
    if (write(clientfd, server_pubkey, 32) != 32)
    {
        perror("Failed to send server public key");
        EVP_PKEY_free(client_key);
        return -1;
    }
    printf("Sent server pubkey\n");
    fflush(stdout);

    // Derive session key
    unsigned char session_key[32];
    if (encrypt_derive_session_key(space->server_key, client_key, session_key) != 0)
    {
        EVP_PKEY_free(client_key);
        perror("Failed to derive session key");
        return -1;
    }
    printf("Session key: %02x%02x%02x%02x...\n", session_key[0], session_key[1], session_key[2], session_key[3]);
    EVP_PKEY_free(client_key);

    // Read message length with a loop
    uint32_t msg_len;
    total_read = 0;
    while (total_read < sizeof(msg_len))
    {
        ssize_t bytes_read = read(clientfd, (char *)&msg_len + total_read, sizeof(msg_len) - total_read);
        if (bytes_read <= 0)
        {
            fprintf(stderr, "Read failed: %zd, total: %zu/%zu\n", bytes_read, total_read, sizeof(msg_len));
            return -1;
        }
        total_read += bytes_read;
        printf("Read %zd bytes, total %zu/%zu for msg_len\n", bytes_read, total_read, sizeof(msg_len));
    }
    msg_len = ntohl(msg_len); // Convert from network (big-endian) to host order
    if (msg_len < 12 + 32 + 16)
    { // Minimum: nonce + space_id + tag
        fprintf(stderr, "Invalid message length: %u\n", msg_len);
        return -1;
    }
    printf("Received message length: %u\n", msg_len);

    // Single allocation of msg_buffer
    unsigned char *msg_buffer = calloc(msg_len, sizeof(unsigned char));
    if (!msg_buffer)
    {
        perror("Failed to allocate message buffer");
        return -1;
    }
    total_read = 0;
    while (total_read < msg_len)
    {
        ssize_t bytes_read = read(clientfd, msg_buffer + total_read, msg_len - total_read);
        if (bytes_read <= 0)
        {
            fprintf(stderr, "Read failed: %zd, total: %zu/%u\n", bytes_read, total_read, msg_len);
            free(msg_buffer);
            return -1;
        }
        total_read += bytes_read;
        printf("Read %zd bytes, total %zu/%u\n", bytes_read, total_read, msg_len);
    }

    unsigned char *nonce = msg_buffer;
    // unsigned char *space_id = msg_buffer + 12;
    unsigned char *ciphertext = msg_buffer + 12 + 32;
    size_t ciphertext_len = msg_len - 12 - 32;

    uint8_t *plaintext = NULL;
    size_t plaintext_len;
    if (encrypt_decrypt_message(session_key, nonce, ciphertext, ciphertext_len, &plaintext, &plaintext_len) != 0)
    {
        free(msg_buffer);
        perror("Failed to decrypt message");
        return -1;
    }
    free(msg_buffer);

    if (plaintext_len < 1)
    {
        free(plaintext);
        fprintf(stderr, "Empty message\n");
        return -1;
    }

    uint8_t op = plaintext[0];
    uint8_t *tuple_buffer = plaintext + 1; // Point to tuple data
    Tuple *req = tuple_deserialize(&tuple_buffer, plaintext_len - 1);
    free(plaintext);
    if (!req)
    {
        perror("Failed to deserialize tuple");
        return -1;
    }
    printf("Operation: %u\n", op);
    if (req->id == 0)
    {
        req->id = generate_tuple_id();
    }

    // Apply the operation:

    Tuple *res = NULL;
    switch (op)
    {
    case OP_PUT:
        printf("Handling OP_PUT\n");
        uint64_t new_id = req->id;
        if (tuple_space_put(space, req, &new_id) < 0)
        {
            tuple_deinit(req);
            fprintf(stderr, "tuple_space_put failed\n");
            return -1;
        }
        printf("Calling notify_clients/resources with ID: %lu\n", req->id);
        network_notify_clients(notify_args, req->id);
        break;
    case OP_TAKE:
        res = tuple_space_take(space, req);
        if (!res)
        {
            tuple_deinit(req);
            fprintf(stderr, "tuple_space_take: No matching tuple found\n");
            break; // Send empty response
        }
        break;
    case OP_GET:
        res = tuple_space_get(space, req->id);
        if (!res)
        {
            tuple_deinit(req);
            fprintf(stderr, "tuple_space_get: No matching tuple found\n");
            break; // Send empty response
        }
        printf("tuple_space_read: Read tuple ID: %lu\n", res->id);
        break;
    case OP_REMOVE:
        if (tuple_space_remove(space, req->id) == false)
        {
            tuple_deinit(req);
            fprintf(stderr, "tuple_space_remove: No tuple with ID %zu found\n", req->id);
        }
        break;
    case OP_RLIST:
        res = tuple_space_resource_query(space, req->resource_id);
        if (!res)
        {
            tuple_deinit(req);
            fprintf(stderr, "tuple_space_resource_query: No tuples found for resource ID %lu\n", req->resource_id);
            break; // Send empty response
        }
        break;
    default:
        tuple_deinit(req);
        fprintf(stderr, "Unknown operation: %u\n", op);
        return -1;
    }

    uint8_t *out_buffer = NULL;
    size_t out_len = 0;
    if (res)
    {
        printf("Preparing to serialize tuple ID: %lu, elements_len: %zu\n", res->id, res->elements_len);
        if (tuple_serialize(res, &out_buffer, &out_len) != 0)
        {
            tuple_deinit(res);
            fprintf(stderr, "tuple_serialize failed\n");
            return -1;
        }
        // printf("Serialized tuple ID: %lu, out_len: %zu\n", res->id, out_len);

        unsigned char nonce_out[12];
        if (RAND_bytes(nonce_out, sizeof(nonce_out)) != 1)
        {
            free(out_buffer);
            fprintf(stderr, "Failed to generate nonce: %s\n", ERR_error_string(ERR_get_error(), NULL));
            tuple_deinit(res);
            return -1;
        }

        uint8_t *encrypted = NULL;
        size_t encrypted_len = 0;
        if (out_buffer)
        {
            printf("Encrypting response, plaintext length: %zu\n", out_len);
            if (encrypt_encrypt_message(session_key, nonce_out, out_buffer, out_len, &encrypted, &encrypted_len) != 0)
            {
                free(out_buffer);
                fprintf(stderr, "Failed to encrypt response\n");
                tuple_deinit(res);
                return -1;
            }
            free(out_buffer);
        }
        else
        {
            encrypted_len = 0; // Empty response
        }

        const size_t NONCE_LEN = 12;
        uint32_t total_len = htonl(4 + NONCE_LEN + encrypted_len); // Network byte order, explicit nonce length
        struct iovec iov[3] = {
            {&total_len, sizeof(total_len)},
            {nonce_out, NONCE_LEN},
            {encrypted, encrypted_len}};
        struct msghdr msg = {0, 0, iov, 3, 0, 0, 0};
        ssize_t sent_bytes = sendmsg(clientfd, &msg, 0);
        if (sent_bytes < 0)
        {
            free(encrypted);
            perror("Failed to send response");
            tuple_deinit(res);
            return -1;
        }
        size_t expected_bytes = 4 + NONCE_LEN + encrypted_len;
        if (sent_bytes != (ssize_t)expected_bytes)
        {
            free(encrypted);
            fprintf(stderr, "Sent %zd bytes, expected %zu (length=%u, nonce=%zu, encrypted=%zu)\n",
                    sent_bytes, expected_bytes, ntohl(total_len), NONCE_LEN, encrypted_len);
            tuple_deinit(res);
            return -1;
        }
        printf("Sent response, length: %u, bytes sent: %zd\n", ntohl(total_len), sent_bytes);
        fflush(stdout);
        free(encrypted);
    }
    else
    {
        tuple_deinit(res);
    }
    return 0;
}

void network_notify_clients(NotifyArgs *args, uint64_t tuple_id)
{
    printf("notify_clients/resources called with tuple_id: %lu\n", tuple_id);
    pthread_rwlock_rdlock(&args->space->rwlock);
    Tuple *tuple = tuple_space_get(args->space, tuple_id);
    if (!tuple)
    {
        printf("Tuple %lu not found\n", tuple_id);
        pthread_rwlock_unlock(&args->space->rwlock);
        return;
    }
    char key[32];
    snprintf(key, sizeof(key), "%s%lu", tuple->resource_id ? "r" : "c",
             tuple->resource_id ? tuple->resource_id : tuple->client_id);
    bool is_resource = tuple->resource_id && !tuple->request_id;
    printf("Target key: %s, is_resource: %d\n", key, is_resource);
    pthread_rwlock_unlock(&args->space->rwlock);

    pthread_mutex_lock(&args->mutex);
    int *fd_ptr = g_hash_table_lookup(args->clients, key);
    if (fd_ptr)
    {
        uint64_t net_id = htobe64(tuple_id);
        printf("Found fd: %d, sending notification\n", *fd_ptr);
        if (write(*fd_ptr, &net_id, sizeof(net_id)) != sizeof(net_id))
        {
            perror("Failed to notify client");
            close(*fd_ptr);
            g_hash_table_remove(args->clients, key);
        }
        else
        {
            printf("Notification sent to fd: %d\n", *fd_ptr);
        }
    }
    else
    {
        printf("No client found for key: %s\n", key);
    }
    pthread_mutex_unlock(&args->mutex);
}

// Add at top of tuple_network.c
extern volatile sig_atomic_t keep_running;

void *network_notify_thread(void *arg)
{
    NotifyArgs *args = (NotifyArgs *)arg;
    struct epoll_event events[MAX_EVENTS];
    int epollfd = args->epollfd;

    while (keep_running) // Changed from while (1)
    {
        int nfds = epoll_wait(epollfd, events, MAX_EVENTS, -1);
        if (nfds < 0)
        {
            if (keep_running)
            {
                perror("notify epoll_wait failed");
            }
            break;
        }
        for (int i = 0; i < nfds; i++)
        {
            if (events[i].events & EPOLLIN)
            {
                int clientfd = events[i].data.fd;
                uint64_t id_buf[2];
                ssize_t n = read(clientfd, id_buf, sizeof(id_buf));
                if (n <= 0)
                {
                    epoll_ctl(epollfd, EPOLL_CTL_DEL, clientfd, NULL);
                    pthread_mutex_lock(&args->mutex);
                    g_hash_table_remove(args->clients, GUINT_TO_POINTER(clientfd));
                    pthread_mutex_unlock(&args->mutex);
                    close(clientfd);
                    continue;
                }
                uint64_t id = be64toh(id_buf[0]);
                uint8_t is_resource = id_buf[1];
                char *key = calloc(32, sizeof(char));
                snprintf(key, 32, "%s%lu", is_resource ? "r" : "c", id);
                printf("Registering fd %d with key: %s\n", clientfd, key);
                pthread_mutex_lock(&args->mutex);
                g_hash_table_insert(args->clients, key, g_memdup2(&clientfd, sizeof(clientfd)));
                pthread_mutex_unlock(&args->mutex);
            }
        }
    }
    return NULL;
}

void *network_client_thread(void *arg)
{
    ClientArgs *args = (ClientArgs *)arg;
    struct epoll_event events[MAX_EVENTS];

    while (1)
    {
        int nfds = epoll_wait(args->epollfd, events, MAX_EVENTS, -1);
        for (int i = 0; i < nfds; i++)
        {
            if (events[i].events & EPOLLIN)
            {
                int clientfd = events[i].data.fd;
                if (network_handle_client(clientfd, args->space, args->notify_args) < 0)
                {
                    epoll_ctl(args->epollfd, EPOLL_CTL_DEL, clientfd, NULL);
                    close(clientfd);
                }
                else
                {
                    close(clientfd);
                }
            }
        }
    }
    free(args);
    return NULL;
}