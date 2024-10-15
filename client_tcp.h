#ifndef CLIENT_TCP_H
#define CLIENT_TCP_H

#include <netinet/in.h>

struct client_tcp
{
	int fd;
	struct sockaddr_in server_addr;
};



struct client_tcp *client_tcp_create(void);
void client_tcp_destroy(struct client_tcp *client);
int client_tcp_connect(struct client_tcp *client,
				short port, const char *ip);

#endif //CLIENT_TCP_H
