// man inet(3)
#define _DEFAULT_SOURCE

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// man socket
#include <sys/socket.h>
#include <sys/types.h>

// for getprotobyname
#include <netdb.h>

// for inet_ntoa
#include <netinet/in.h>
#include <arpa/inet.h>

#include "client_udp.h"

#define DEBUG_TRACE_TO_STDERR
#ifdef DEBUG_TRACE_TO_STDERR

#define debug_trace()\
	do { fprintf(stderr, "[!] Error in %s() [%s #%i]\n",\
		__func__, __FILE__, __LINE__ - 1); } while(0)

#define debug_trace_errno()\
	do { fprintf(stderr, "[!] Error in %s() [%s #%i] : %s\n",\
		__func__, __FILE__, __LINE__ - 1, strerror(errno));\
	     errno = 0; } while(0)
#else

#define debug_trace()\
		((void)(0))

#define debug_trace_errno()\
		((void)(0))

#endif //DEBUG_TRACE_TO_STDERR


#define ARR_SIZE(arr)\
	(sizeof(arr) / sizeof(*arr))

#define UNUSED_VAR(var)\
	(void)(var)

static void client_udp_free(struct client_udp *client);
static struct client_udp *client_udp_init(short self_port, const char *self_ip);

int client_udp_set_server(struct client_udp *client,
			short server_port, const char *server_ip)
{
	int err;

	memset(&(client->server_addr), 0, sizeof(client->server_addr));
	client->server_addr.sin_family = AF_INET;
	client->server_addr.sin_port = htons(server_port);
	err = inet_aton(server_ip, &(client->server_addr.sin_addr));
	if(err == 0) {
		debug_trace();
		return -1;
	}

	return 0;
}

struct client_udp *client_udp_create(short self_port, const char *self_ip)
{
	struct client_udp *client;
	struct protoent *prot;
	int err;
	int optval = 1;

	client = client_udp_init(self_port, self_ip);
	if(client == NULL) {
		debug_trace();
		goto err_out;
	}

	prot = getprotobyname("udp");
	if(prot == NULL) {
		debug_trace_errno();
		goto err_out;
	}

	client->fd = socket(AF_INET, SOCK_DGRAM, prot->p_proto);
	if(client->fd == -1) {
		debug_trace_errno();
		goto err_out;
	}	

	err = setsockopt(client->fd, SOL_SOCKET, SO_REUSEADDR, 
						&optval, sizeof(optval));
	if(err == -1) {
		debug_trace_errno();
		goto err_out;
	}


	err = bind(client->fd, (struct sockaddr *) &(client->self_addr),
					sizeof(client->self_addr));
	if(err == -1) {
		debug_trace_errno();
		goto err_out;
	}

	return client;

err_out:
	
	client_udp_free(client);
	return NULL;
}

void client_udp_destroy(struct client_udp *client)
{
	client_udp_free(client);
}

static struct client_udp *client_udp_init(short self_port, const char *self_ip)
{
	int err;
	struct client_udp *client;

	client = malloc(sizeof(*client));
	if(client == NULL) {
		debug_trace_errno();
		return NULL;
	}

	client->fd = -1;

	memset(&(client->self_addr), 0, sizeof(client->self_addr));
	client->self_addr.sin_family = AF_INET;
	client->self_addr.sin_port = htons(self_port);
	err = inet_aton(self_ip, &(client->self_addr.sin_addr));
	/* returns 0 on failure. Man page says errno is not set. */
	if(err == 0) {
		debug_trace();
		free(client);
		return NULL;
	}

	
	return client;
}

static void client_udp_free(struct client_udp *client)
{
	if(client == NULL)
		return;
	
	if(client->fd != -1)
		close(client->fd);

	free(client);
}



