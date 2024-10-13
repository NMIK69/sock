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

// for killpg
#include <signal.h>

#include "server_udp.h"


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

/* used reccources and references
- https://www.linuxhowtos.org/C_C++/socket.htm
- http://www.cs.columbia.edu/~danr/courses/6761/Fall00/hw/pa1/6761-sockhelp.pdf
*/

struct server_udp
{
	struct sockaddr_in addr;
	int fd;
	int listener_pid;
	struct sigaction old_sa;
	cli_handler_udp handler;
};

static struct server_udp *server_udp_init(short port, const char *ip);
static void server_udp_free(struct server_udp *server);
static void listener_stop(int s);
static void process_listen_inf(struct server_udp *server);
static void server_udp_sigchld_handler(int s);

/* only relevant in the forked process for running the server. */
static int listener_is_running;


int server_udp_start(struct server_udp *server)
{
	int pid;
	int err;
	struct sigaction sa;	

	/* sigchld handler for when listener dies unexpectedly */
	sa.sa_handler = server_udp_sigchld_handler;
	/* so that I don't miss/ignore sigchlds */
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART;

	err = sigaction(SIGCHLD, &sa, &(server->old_sa));
	if(err == -1) {
		debug_trace_errno();
		return -1;
	}

	pid = fork();

	if(pid == -1) {
		debug_trace_errno();
		return -1;
	}
	else if(pid == 0) {
		/* calls _exit() */
		process_listen_inf(server);	
	}

	/* else pid is child (listener) pid */
	server->listener_pid = pid;

	return 0;
}

int server_udp_shutdown(struct server_udp *server)
{
	int err;
	
	/* remove sighandler for sigchld so that i can use waitpid to wait for
	 * the listener to terminate */
	err = sigaction(SIGCHLD, &(server->old_sa), NULL);
	if(err == -1) {
		debug_trace_errno();
		return -1;
	}

	err = kill(server->listener_pid, SIGUSR1);
	if(err == -1) {
		debug_trace_errno();
		return -1;
	}
	waitpid(server->listener_pid, NULL, 0);

	server_udp_free(server);

	return 0;
}

struct server_udp *server_udp_create(short port, 
				const char *ip,
				cli_handler_udp handler)
{
	struct server_udp *server;
	struct protoent *prot;
	int err;
	int optval = 1;

	server = server_udp_init(port, ip);
	if(server == NULL) {
		debug_trace();
		goto err_out;
	}
	server->handler = handler;

	/* man page says it can also be read from /etc/protocols */
	/* and apperently you don't free the returned pointer. */
	prot = getprotobyname("udp");
	if(prot == NULL) {
		debug_trace_errno();
		goto err_out;
	}

	server->fd = socket(AF_INET, SOCK_DGRAM, prot->p_proto);
	if(server->fd == -1) {
		debug_trace_errno();
		goto err_out;
	}	

	err = setsockopt(server->fd, SOL_SOCKET, SO_REUSEADDR, 
						&optval, sizeof(optval));
	if(err == -1) {
		debug_trace_errno();
		goto err_out;
	}


	err = bind(server->fd, (struct sockaddr *) &(server->addr),
					sizeof(server->addr));
	if(err == -1) {
		debug_trace_errno();
		goto err_out;
	}

	return server;

err_out:
	
	server_udp_free(server);
	
	return NULL;
}

void print_server_udp_info(const struct server_udp *server)
{
	printf("[*] Server Info:\n"
			"\tTYPE: UDP\n"
			"\tIP  : %s\n"
			"\tPORT: %d\n",
			inet_ntoa(server->addr.sin_addr),
			ntohs(server->addr.sin_port));
}


static void listener_stop(int s)
{
	UNUSED_VAR(s);

	printf("[*] Listener shutting down\n");

	listener_is_running = 0;
}

static struct server_udp *server_udp_init(short port, const char *ip)
{
	
	int err;
	struct server_udp *server;

	server = malloc(sizeof(*server));
	if(server == NULL) {
		debug_trace_errno();
		return NULL;
	}

	server->fd = -1;
	memset(&(server->addr), 0, sizeof(server->addr));
	server->addr.sin_family = AF_INET;
	server->addr.sin_port = htons(port);
	err = inet_aton(ip, &(server->addr.sin_addr));
	/* returns 0 on failure. Man page says errno is not set. */
	if(err == 0) {
		debug_trace();
		free(server);
		return NULL;
	}
	
	return server;
}

static void server_udp_free(struct server_udp *server)
{
	if(server == NULL)
		return;
	
	if(server->fd != -1)
		close(server->fd);

	free(server);
}

static void process_listen_inf(struct server_udp *server)
{
	struct sigaction sa;	
	int err;
	ssize_t nb_recv;
	ssize_t nb_send;
	struct sockaddr_in peer_addr;
	socklen_t peer_addr_len = sizeof(peer_addr);

	char recv_buf[1024];
	char *send_buf = NULL;
	size_t send_buf_len = 0;

	sigemptyset(&sa.sa_mask);
	sa.sa_handler = listener_stop;
	/* dont use restart */
	/* Then i can use errno to check if it is "interrupted syscall" */
	sa.sa_flags = 0;
	err = sigaction(SIGUSR1, &sa, NULL);
	if(err == -1) {
		debug_trace_errno();
		_exit(EXIT_FAILURE);
	}

	listener_is_running = 1;
	while(listener_is_running == 1) {
		nb_recv = recvfrom(server->fd, 
				   recv_buf, 
				   ARR_SIZE(recv_buf), 
				   0,
				   (struct sockaddr *) &peer_addr,
				   &peer_addr_len);

		if(peer_addr_len != sizeof(peer_addr))
			debug_trace();

		if(nb_recv == -1) {
			/* man 7 signal */
			if(errno == EINTR)
				break;
			else
				debug_trace_errno();
		}


		/* user provided handler callback */
		err = server->handler(recv_buf, nb_recv, &send_buf, &send_buf_len);

		if(err == 0) {
			nb_send = sendto(server->fd,
					 send_buf,
					 send_buf_len,
					 0,
					 (struct sockaddr *) &peer_addr,
					 peer_addr_len);

			if(nb_send == -1) {
				/* man 7 signal */
				if(errno == EINTR)
					break;
				else 
					debug_trace_errno();
			}
		}
	}

	printf("[*] Listener shut down.\n");
	_exit(EXIT_SUCCESS);
}

static void server_udp_sigchld_handler(int s)
{
	UNUSED_VAR(s);

	printf("[!] Listener encountered unexpected error\n");
	wait(NULL);
}
