#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "client_udp.h"
#include "client_tcp.h"

// for inet_ntoa
#include <netinet/in.h>
#include <arpa/inet.h>

#include <sys/socket.h>
#include <sys/types.h>


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

static void test_tcp(void);
static void test_udp(void);

int main(void)
{
	UNUSED_VAR(test_udp);
	UNUSED_VAR(test_tcp);

	//test_tcp();
	test_udp();
}

static void test_udp(void)
{
	int err;
	ssize_t nb_send;
	ssize_t nb_recv;
	struct client_udp *client;
	char buf[200];
	const char *msg = "test 123";	

	struct sockaddr_in recv_addr;
	socklen_t recv_addr_len = sizeof(recv_addr);


	client = client_udp_create(8080, "127.0.0.1");
	if(client == NULL) {
		printf("[!] Failed to crate UDP client\n");
		goto out;
	}

	err = client_udp_set_server(client, 8000, "127.0.0.1");
	if(err == -1) {
		printf("[!] Failed to set UDP server\n");
		goto out;
	}

	printf("[*] UDP client successfully created\n");

	nb_send = sendto(client->fd, msg, strlen(msg), 0,
			(struct sockaddr *) &(client->server_addr),
			sizeof(client->server_addr));
	if(nb_send == -1) {
		debug_trace_errno();
		goto out;
	}

	printf("[*] Send: \"%s\"\n", msg);

	nb_recv = recvfrom(client->fd, buf, ARR_SIZE(buf), 0,
				(struct sockaddr *) &(recv_addr),
				&recv_addr_len);
	if(nb_recv == -1) {
		debug_trace_errno();
		goto out;
	}
	buf[nb_recv] = '\0';


	/* apperently you don't free the pointer */
	char *recv_ip = inet_ntoa(recv_addr.sin_addr);
	short recv_port = ntohs(recv_addr.sin_port);
	printf("[*] Received: \"%s\" from %s : %d\n",
		buf, recv_ip, recv_port);

	getchar();

out:
	printf("[*] Shutting client down\n");
	client_udp_destroy(client);
}

static void test_tcp(void)
{
	int err;
	ssize_t nb_send;
	ssize_t nb_recv;
	struct client_tcp *client;
	char buf[200];
	const char *msg = "test 123";	

	client = client_tcp_create();

	err = client_tcp_connect(client, 8000, "127.0.0.1");
	if(err == -1) {
		printf("[!] Failed to connect\n");
		return;
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
	client_tcp_destroy(client);
}


