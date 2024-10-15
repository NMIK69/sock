#ifndef CLIENT_UDP_H
#define CLIENT_UDP_H

#include <netinet/in.h>

struct client_udp
{
	int fd;
	struct sockaddr_in self_addr;
	struct sockaddr_in server_addr;
};

struct client_udp *client_udp_create(short self_port, const char *self_ip);
void client_udp_destroy(struct client_udp *client);
int client_udp_set_server(struct client_udp *client,
			short server_port, const char *server_ip);


#endif //CLIENT_UDP_H
