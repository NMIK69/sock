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

#include "server_tcp.h"


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


/* pure autism: 

- inet_ntoa -> network to ascii
- inet_aton -> asii to network
//server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
//server_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
//server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
//inet_aton("127.0.0.1", &(server_addr.sin_addr));

*/

/* used reccources and references
- https://github.com/skuhl/sys-prog-examples/blob/master/simple-examples/sigaction.c
- https://www.linuxhowtos.org/C_C++/socket.htm
- http://www.cs.columbia.edu/~danr/courses/6761/Fall00/hw/pa1/6761-sockhelp.pdf
*/


/* TODO:
	- [ ] Track pids (in listener) in a more robust way.
*/

struct server_tcp
{
	/* man ip(7) */
	struct sockaddr_in addr;
	int fd;
	int listener_pid;
	struct sigaction old_sa;
	cli_handler_tcp handler;
};


static struct server_tcp *server_tcp_init(short port,
				const char *ip);
static void server_tcp_free(struct server_tcp *server);

static void process_listen_inf(struct server_tcp *server);
static void process_handle_connection(int peer_fd, struct sockaddr_in addr,
					cli_handler_tcp handler);

static void handle_connection_stop(int s);
static void listener_stop(int s);
static void listener_sigchld_handler(int s);
static void server_tcp_sigchld_handler(int s);

/* only relevant in the forked process for running the server. */
static int listener_is_running;
static int handler_is_running;

int server_tcp_start(struct server_tcp *server)
{
	int pid;
	int err;
	struct sigaction sa;	

	sa.sa_handler = server_tcp_sigchld_handler;
	//sigfillset(&sa.sa_mask);
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

int server_tcp_shutdown(struct server_tcp *server)
{
	int err;
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

	server_tcp_free(server);

	return 0;
}

struct server_tcp *server_tcp_create(short port, 
				const char *ip,
				int backlog,
				cli_handler_tcp handler)
{
	struct server_tcp *server;
	struct protoent *prot;
	int err;
	int optval = 1;

	server = server_tcp_init(port, ip);
	if(server == NULL) {
		debug_trace();
		goto err_out;
	}
	server->handler = handler;

	/* man page says it can also be read from /etc/protocols */
	/* and apperently you don't free the returned pointer. */
	prot = getprotobyname("tcp");
	if(prot == NULL) {
		debug_trace_errno();
		goto err_out;
	}

	server->fd = socket(AF_INET, SOCK_STREAM, prot->p_proto);
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

	
	err = listen(server->fd, backlog);
	if(err == -1) {
		debug_trace_errno();
		goto err_out;
	}

	return server;

err_out:
	
	server_tcp_free(server);
	
	return NULL;
}

void print_server_tcp_info(const struct server_tcp *server)
{
	printf("[*] Server Info:\n"
			"\tTYPE: TCP\n"
			"\tIP  : %s\n"
			"\tPORT: %d\n",
			inet_ntoa(server->addr.sin_addr),
			ntohs(server->addr.sin_port));
}

static void handle_connection_stop(int s)
{
	UNUSED_VAR(s);

	printf("[*] Closing connection (listener command)\n");

	handler_is_running = 0;
}

static void listener_stop(int s)
{
	UNUSED_VAR(s);

	printf("[*] Listener shutting down\n");

	listener_is_running = 0;
}

static void listener_sigchld_handler(int s)
{
	UNUSED_VAR(s);

	printf("[*] Connection handler zombie reaped\n");
	wait(NULL);
}

static void server_tcp_sigchld_handler(int s)
{
	UNUSED_VAR(s);

	printf("[!] Listener encountered unexpected error\n");
	wait(NULL);
}


static struct server_tcp *server_tcp_init(short port, const char *ip)
{
	
	int err;
	struct server_tcp *server;

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
	/* returns 0 on failure wtf. Man page says errno is not set. */
	if(err == 0) {
		debug_trace();
		free(server);
		return NULL;
	}
	
	return server;
}


static void server_tcp_free(struct server_tcp *server)
{
	if(server == NULL)
		return;
	
	if(server->fd != -1)
		close(server->fd);

	free(server);
}

static void process_handle_connection(int peer_fd, struct sockaddr_in client_addr,
					cli_handler_tcp handler)
{
	struct sigaction sa;	
	int err;
	ssize_t nb_recv;
	ssize_t nb_send;

	char recv_buf[1024];
	char *send_buf = NULL;
	size_t send_buf_len = 0;

	printf("[*] Accepted connection from: %s\n",
			inet_ntoa(client_addr.sin_addr));

	/* dont use restart */
	/* Then i can use errno to check if it is "interrupted syscall" */
	sigfillset(&sa.sa_mask);
	sa.sa_handler = handle_connection_stop;
	sa.sa_flags = 0;
	err = sigaction(SIGUSR1, &sa, NULL);
	if(err == -1) {
		debug_trace_errno();
		close(peer_fd);
		_exit(EXIT_FAILURE);
	}

	handler_is_running = 1;
	while(handler_is_running == 1) {

		nb_recv = recv(peer_fd, recv_buf, ARR_SIZE(recv_buf), 0);
		/* peer closed connection */
		if(nb_recv == 0)
			break;

		if(nb_recv == -1) {
			/* man 7 signal */
			//if(errno == ERESTART || errno == EINTR)
			if(errno == EINTR)
				break;
			else
				debug_trace_errno();
		}

		err = handler(recv_buf, nb_recv, &send_buf, &send_buf_len);

		if(err == 0) {
			nb_send = send(peer_fd, send_buf, send_buf_len, 0);
			/* peer closed connection */
			if(nb_send == 0)
				break;

			if(nb_send == -1) {
				/* man 7 signal */
				//if(errno == ERESTART || errno == EINTR)
				if(errno == EINTR)
					break;
				else 
					debug_trace_errno();
			}
		}
	}
	

	close(peer_fd);
	_exit(EXIT_SUCCESS);
}

static void process_listen_inf(struct server_tcp *server)
{
	struct sigaction sa;	
	struct sigaction old_sa;
	int err;
	int pid;
	int child_pids[500];
	size_t num_chlds = 0;
	int peer_fd;
	struct sockaddr_in peer_addr;
	socklen_t peer_addr_len = sizeof(peer_addr);

	//sigfillset(&sa.sa_mask);
	sigemptyset(&sa.sa_mask);

	sa.sa_handler = listener_sigchld_handler;
	sa.sa_flags = SA_RESTART;
	err = sigaction(SIGCHLD, &sa, &old_sa);
	if(err == -1) {
		debug_trace_errno();
		_exit(EXIT_FAILURE);
	}

	/* dont use restart */
	/* Then i can use errno to check if it is "interrupted syscall" */
	sa.sa_handler = listener_stop;
	sa.sa_flags = 0;
	err = sigaction(SIGUSR1, &sa, &old_sa);
	if(err == -1) {
		debug_trace_errno();
		_exit(EXIT_FAILURE);
	}

	listener_is_running = 1;
	while(listener_is_running == 1) {
		peer_fd = accept(server->fd, 
				(struct sockaddr *) &peer_addr, 
				&peer_addr_len);	
				
		if(peer_fd == -1) {
			/* if it was interrupted by signal, then it should be by
			 * sigusr1 */
			/* man 7 signal */
			//if(errno == ERESTART || errno == EINTR)
			if(errno == EINTR)
				break;


			debug_trace_errno();
			continue;
		}

		
		pid = fork();	
		if(pid == -1) {
			debug_trace_errno();
			close(peer_fd);
		}
		else if(pid == 0) {
			/* close copy of listener fd.*/
			close(server->fd);
			/* calls _exit() */
			process_handle_connection(peer_fd, peer_addr,
						server->handler);
		}
		else {
			/* I'm just accepting connections I don't care about
			 * talking to peer. */
			child_pids[num_chlds++] = pid;
			close(peer_fd);
		}
	}

	/* restore / remove signal handlers */	
	err = sigaction(SIGUSR1, &old_sa, NULL);
	if(err == -1) {
		debug_trace_errno();
		_exit(EXIT_FAILURE);
	}
	err = sigaction(SIGCHLD, &old_sa, NULL);
	if(err == -1) {
		debug_trace_errno();
		_exit(EXIT_FAILURE);
	}

	/* stop all connection handlers */
	for(size_t i = 0; i < num_chlds; i++) {
		err = kill(child_pids[i], SIGUSR1);
		/* pid might already be dead. Check for ERSCH. */
		if(err == -1) {
			if(errno != ESRCH)
				debug_trace_errno();
		}
		else {
			err = waitpid(child_pids[i], NULL, 0);
			if(err == -1) {
				debug_trace_errno();
				/* TODO: do i _exit here ? */
			}
		}
	}

	printf("[*] All Connection shut down.\n");
	printf("[*] Listener shut down.\n");

	_exit(EXIT_SUCCESS);
}
