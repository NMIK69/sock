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

#include "client_tcp.h"

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

static void client_tcp_free(struct client_tcp *client);

struct client_tcp *client_tcp_create(void)
{
	struct client_tcp *client;
	struct protoent *tcp_prot;
	int optval = 1;
	int err;

	client = malloc(sizeof(*client));
	if(client == NULL) {
		debug_trace_errno();
		return NULL;
	}

	/* man page says it can also be read from /etc/protocols */
	/* and apperently you don't free the returned pointer. */
	tcp_prot = getprotobyname("tcp");
	if(tcp_prot == NULL) {
		debug_trace_errno();
		goto err_out;
	}

	client->fd = socket(AF_INET, SOCK_STREAM, tcp_prot->p_proto);
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
	
	return client;
	
err_out:
	client_tcp_free(client);
	return NULL;
}

void client_tcp_destroy(struct client_tcp *client)
{
	client_tcp_free(client);
}

int client_tcp_connect(struct client_tcp *client,
				short port, const char *ip)
{
	int err;

	memset(&(client->server_addr), 0, sizeof(client->server_addr));
	client->server_addr.sin_family = AF_INET;
	client->server_addr.sin_port = htons(port);
	err = inet_aton(ip, &(client->server_addr.sin_addr));
	/* returns 0 on failure wtf. Man page says errno is not set. */
	if(err == 0) {
		debug_trace();
		return -1;
	}

	err = connect(client->fd, (struct sockaddr *)(&(client->server_addr)),
				sizeof(client->server_addr));
	
	if(err == -1) {
		debug_trace_errno();
		return -1;
	}


	return 0;
}

static void client_tcp_free(struct client_tcp *client)
{
	if(client == NULL)
		return;
	
	close(client->fd);
	free(client);
}
