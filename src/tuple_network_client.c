// tuple_network_client.c
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include <string.h>

int network_connect_client(const char *host, int port, int *clientfd)
{
    struct hostent *he;
    struct sockaddr_in server_addr = {0};

    *clientfd = socket(AF_INET, SOCK_STREAM, 0);
    if (*clientfd == -1)
        return -1;

    he = gethostbyname(host);
    if (he == NULL || he->h_addr_list[0] == NULL)
    {
        close(*clientfd);
        return -1;
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    memcpy(&server_addr.sin_addr, he->h_addr_list[0], he->h_length);

    if (connect(*clientfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1)
    {
        close(*clientfd);
        return -1;
    }
    return 0;
}