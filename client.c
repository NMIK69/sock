// man inet(3)
#define _DEFAULT_SOURCE

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>

// man socket
#include <sys/socket.h>
#include <sys/types.h>

// for getprotobyname
#include <netdb.h>

// for inet_ntoa
#include <netinet/in.h>
#include <arpa/inet.h>

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


struct client_tcpip
{
	int fd;
	struct sockaddr_in server_addr;
};


struct client_tcpip *client_tcpip_create(void);
void client_tcpip_destory(struct client_tcpip *client);
int client_tcpip_connect(struct client_tcpip *client,
				short port, const char *ip);
static void client_tcpip_free(struct client_tcpip *client);


int main(void)
{

	int err;
	ssize_t nb_send;
	ssize_t nb_recv;
	struct client_tcpip *client;
	char buf[200];
	const char *msg = "test 123";	

	client = client_tcpip_create();

	err = client_tcpip_connect(client, 8000, "127.0.0.1");
	if(err == -1) {
		printf("[*] Failed to connect\n");
		return -1;
	}

	printf("[*] Connection successfull\n");
	
	nb_send = send(client->fd, msg, strlen(msg), 0);
	if(nb_send == 0) {
		printf("[*] Server closed connection\n");
		goto out;
	}
	else if(nb_send == -1) {
		debug_trace_errno();
		goto out;
	}

	printf("[*] Send: %s\n", msg);

	nb_recv = recv(client->fd, buf, ARR_SIZE(buf), 0);
	if(nb_recv == 0) {
		printf("[*] Server closed connection\n");
		goto out;
	}
	else if(nb_recv == -1) {
		debug_trace_errno();
		goto out;
	}
	buf[nb_recv] = '\0';


	printf("[*] Received: %s\n", buf);

	getchar();

out:
	printf("[*] Shutting client down\n");
	client_tcpip_destory(client);
	return 0;
}

int client_tcpip_connect(struct client_tcpip *client,
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

struct client_tcpip *client_tcpip_create(void)
{
	struct client_tcpip *client;
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
	client_tcpip_free(client);
	return NULL;
}

void client_tcpip_destory(struct client_tcpip *client)
{
	client_tcpip_free(client);
}


static void client_tcpip_free(struct client_tcpip *client)
{
	if(client == NULL)
		return;
	
	close(client->fd);
	free(client);
}
