#ifndef TUPLE_NETWORK_H
#define TUPLE_NETWORK_H

#include <stdint.h>
#include <sys/epoll.h>
#include <pthread.h>
#include <glib.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include "tuple.h"
#include "tuple_space.h"

#define MAX_EVENTS 10
#define MAX_CLIENTS 1024

typedef struct NotifyArgs
{
    TupleSpace *space;
    GHashTable *clients;
    pthread_mutex_t mutex;
    int epollfd;
} NotifyArgs;

typedef struct
{
    TupleSpace *space;
    NotifyArgs *notify_args;
    int epollfd;
} ClientArgs;

int network_init_server(const char *server_id, int *serverfd, int *notifyfd);
int network_handle_client(int clientfd, TupleSpace *space, NotifyArgs *notify_args);
void network_notify_clients(NotifyArgs *args, uint64_t tuple_id);
void *network_notify_thread(void *arg);
void *network_client_thread(void *arg);

#define SERVER_PORT 42420
#define NOTIFY_PORT 42421

#endif