#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <glib.h>
#include <pthread.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include "tuple.h"
#include "tuple_space.h"
#include "tuple_network.h"

static int server_fd = -1;
static int notify_fd = -1;
static int epoll_fd = -1;
volatile sig_atomic_t keep_running = 1; // Non-static for tuple_network.c

static void signal_handler(int sig)
{
    if (sig == SIGINT)
    {
        printf("Received SIGINT, shutting down...\n");
        keep_running = 0;
        if (server_fd >= 0)
            shutdown(server_fd, SHUT_RDWR);
        if (notify_fd >= 0)
            shutdown(notify_fd, SHUT_RDWR);
        if (epoll_fd >= 0)
            close(epoll_fd);
    }
}

int main(int argc, char *argv[])
{
    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s <server_id>\n", argv[0]);
        return 1;
    }
    const char *server_id = argv[1];
    TupleSpace *space = tuple_space_init(server_id);
    if (!space)
    {
        perror("tuple_space_init failed ... ");
        return 1;
    }

    int serverfd, notifyfd;
    if (network_init_server(server_id, &serverfd, &notifyfd) < 0)
    {
        tuple_space_deinit(space);
        return 1;
    }
    server_fd = serverfd;
    notify_fd = notifyfd;

    NotifyArgs notify_args = {
        .space = space,
        .clients = g_hash_table_new_full(g_str_hash, g_str_equal, free, free),
        .mutex = PTHREAD_MUTEX_INITIALIZER,
        .epollfd = epoll_create1(0)};
    if (notify_args.epollfd < 0)
    {
        perror("epoll_create1 failed for notify thread");
        g_hash_table_destroy(notify_args.clients);
        close(notifyfd);
        close(serverfd);
        tuple_space_deinit(space);
        return 1;
    }
    pthread_t notify_tid;
    if (pthread_create(&notify_tid, NULL, network_notify_thread, &notify_args) != 0)
    {
        perror("pthread_create failed for notify thread");
        close(notify_args.epollfd);
        g_hash_table_destroy(notify_args.clients);
        close(notifyfd);
        close(serverfd);
        tuple_space_deinit(space);
        return 1;
    }
    // No pthread_detach() to keep thread joinable

    int epollfd = epoll_create1(0);
    if (epollfd < 0)
    {
        perror("epoll_create1 failed");
        close(notify_args.epollfd);
        g_hash_table_destroy(notify_args.clients);
        close(notifyfd);
        close(serverfd);
        tuple_space_deinit(space);
        return 1;
    }
    epoll_fd = epollfd;

    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.fd = serverfd;
    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, serverfd, &ev) < 0)
    {
        perror("epoll_ctl failed");
        close(epollfd);
        close(notify_args.epollfd);
        g_hash_table_destroy(notify_args.clients);
        close(notifyfd);
        close(serverfd);
        tuple_space_deinit(space);
        return 1;
    }
    ev.data.fd = notifyfd;
    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, notifyfd, &ev) < 0)
    {
        perror("epoll_ctl failed for notifyfd");
        close(epollfd);
        close(notify_args.epollfd);
        g_hash_table_destroy(notify_args.clients);
        close(notifyfd);
        close(serverfd);
        tuple_space_deinit(space);
        return 1;
    }

    struct sigaction sa = {0};
    sa.sa_handler = signal_handler;
    sa.sa_flags = 0;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGINT, &sa, NULL) == -1)
    {
        perror("Failed to set SIGINT handler");
        close(epollfd);
        close(notify_args.epollfd);
        g_hash_table_destroy(notify_args.clients);
        close(notifyfd);
        close(serverfd);
        tuple_space_deinit(space);
        return 1;
    }

    struct epoll_event events[MAX_EVENTS];
    while (keep_running)
    {
        int nfds = epoll_wait(epollfd, events, MAX_EVENTS, -1);
        if (nfds < 0)
        {
            if (keep_running)
            {
                perror("epoll_wait failed");
            }
            break;
        }
        for (int i = 0; i < nfds; i++)
        {
            if (events[i].data.fd == serverfd)
            {
                int clientfd = accept(serverfd, NULL, NULL);
                if (clientfd < 0)
                {
                    if (keep_running)
                    {
                        perror("accept failed");
                    }
                    continue;
                }
                ClientArgs *args = calloc(1,sizeof(ClientArgs));
                if (!args)
                {
                    close(clientfd);
                    continue;
                }
                args->space = space;
                args->notify_args = &notify_args;
                args->epollfd = epoll_create1(0);
                if (args->epollfd < 0)
                {
                    perror("epoll_create1 failed for client thread");
                    free(args);
                    close(clientfd);
                    continue;
                }
                ev.events = EPOLLIN;
                ev.data.fd = clientfd;
                if (epoll_ctl(args->epollfd, EPOLL_CTL_ADD, clientfd, &ev) < 0)
                {
                    perror("epoll_ctl failed for client");
                    close(args->epollfd);
                    free(args);
                    close(clientfd);
                    continue;
                }
                pthread_t tid;
                if (pthread_create(&tid, NULL, network_client_thread, args) != 0)
                {
                    perror("pthread_create failed");
                    close(args->epollfd);
                    free(args);
                    close(clientfd);
                    continue;
                }
                pthread_detach(tid);
            }
            else if (events[i].data.fd == notifyfd)
            {
                int clientfd = accept(notifyfd, NULL, NULL);
                if (clientfd < 0)
                {
                    if (keep_running)
                    {
                        perror("accept failed for notify");
                    }
                    continue;
                }
                ev.events = EPOLLIN;
                ev.data.fd = clientfd;
                if (epoll_ctl(notify_args.epollfd, EPOLL_CTL_ADD, clientfd, &ev) < 0)
                {
                    perror("epoll_ctl failed for notify client");
                    close(clientfd);
                    continue;
                }
            }
        }
    }

    printf("Cleaning up...\n");
    close(epollfd);
    close(notify_args.epollfd);
    g_hash_table_destroy(notify_args.clients);
    close(notifyfd);
    close(serverfd);
    tuple_space_deinit(space);
    pthread_cancel(notify_tid);
    pthread_join(notify_tid, NULL);
    printf("Server shutdown complete.\n");
    return 0;
}