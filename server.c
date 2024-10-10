#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <assert.h>

#include "sockserv.h"

#define PORT_NUM 8000
#define IP "127.0.0.1"

static int echo_handler(const char *recv_buf, size_t recv_len,
			char **send_buf, size_t *send_len);

int main(void)
{
	int err;
	struct server_tcpip *server;

	server = server_tcpip_create(PORT_NUM,
				     IP,
				     10,
				     echo_handler);
	if(server == NULL)
		return 0;

	print_server_tcpip_info(server);

	err = server_tcpip_start(server);
	if(err == -1)
		return 0;

	getchar();
	
	server_tcpip_shutdown(server);
	
	return 0;
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

