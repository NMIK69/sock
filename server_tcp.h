#ifndef SOCKSERV_H
#define SOCKSERV_H

typedef int (*cli_handler_tcp)(const char *, size_t, char **, size_t *);


/* opaque */
struct server_tcp;

struct server_tcp *server_tcp_create(short port, 
				const char *ip,
				int backlog,
				cli_handler_tcp handler);

int server_tcp_start(struct server_tcp *server);
int server_tcp_shutdown(struct server_tcp *server);
void print_server_tcp_info(const struct server_tcp *server);


#endif //SOCKSERV_H
