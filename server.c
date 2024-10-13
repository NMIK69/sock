#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <assert.h>

#include "server_tcp.h"
#include "server_udp.h"

#define PORT_NUM 8000
#define IP "127.0.0.1"

static int echo_handler(const char *recv_buf, size_t recv_len,
			char **send_buf, size_t *send_len);


static void run_tcp(void);
static void run_udp(void);

int main(void)
{
	//run_tcp();
	run_udp();

	return 0;
}

static void run_tcp(void)
{
	int err;
	struct server_tcp *server;

	server = server_tcp_create(PORT_NUM,
				     IP,
				     10,
				     echo_handler);
	if(server == NULL)
		return;

	print_server_tcp_info(server);

	err = server_tcp_start(server);
	if(err == -1)
		return;

	getchar();
	
	server_tcp_shutdown(server);
}

static void run_udp(void)
{
	int err;
	struct server_udp *server;

	server = server_udp_create(PORT_NUM,
				     IP,
				     echo_handler);
	if(server == NULL)
		return;

	print_server_udp_info(server);

	err = server_udp_start(server);
	if(err == -1)
		return;

	getchar();
	
	server_udp_shutdown(server);
}

static int echo_handler(const char *recv_buf, size_t recv_len,
			char **send_buf, size_t *send_len)
{
	if((*send_buf) == NULL || recv_len > (*send_len)) {
		(*send_buf) = realloc((*send_buf), recv_len);
		if((*send_buf) == NULL) {
			fprintf(stderr, "realloc failed: %s\n", strerror(errno));
			errno = 0;
			return -1;
		}
	}

	(*send_len) = recv_len;

	memcpy((*send_buf), recv_buf, recv_len);

	return 0;
}

