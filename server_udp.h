#ifndef SERVER_UDP_H
#define SERVER_UDP_H

typedef int (*cli_handler_udp)(const char *, size_t, char **, size_t *);

/* opaque */
struct server_udp;

struct server_udp *server_udp_create(short port, 
				const char *ip,
				cli_handler_udp handler);

int server_udp_start(struct server_udp *server);
int server_udp_shutdown(struct server_udp *server);
void print_server_udp_info(const struct server_udp *server);

#endif //SERVER_UDP_H
