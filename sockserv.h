#ifndef SOCKSERV_H
#define SOCKSERV_H

typedef int (*tcpip_cli_handler)(const char *, size_t, char **, size_t *);

struct server_tcpip;

struct server_tcpip *server_tcpip_create(short port, 
				const char *ip,
				int backlog,
				tcpip_cli_handler handler);

int server_tcpip_start(struct server_tcpip *server);
int server_tcpip_shutdown(struct server_tcpip *server);
void print_server_tcpip_info(const struct server_tcpip *server);

#endif //SOCKSERV_H
