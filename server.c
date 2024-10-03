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


#define UNUSED_VAR(var)\
	(void)(var)

#define PORT_NUM 8000

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

struct server_tcpip
{
	/* man ip(7) */
	struct sockaddr_in addr;
	int fd;
};

static struct server_tcpip *server_tcpip_create(short port, 
						const char *ip,
						int backlog);
static int server_tcpip_shutdown(int pid, struct server_tcpip *server);
static struct server_tcpip *server_tcpip_init(short port,
						const char *ip);
static void server_tcpip_free(struct server_tcpip *server);

static void print_server_tcpip_info(struct server_tcpip *server);

static int server_tcpip_start(struct server_tcpip *server);
static void process_listen_inf(struct server_tcpip *server);
static void process_handle_connection(int peer_fd, struct sockaddr_in addr);


/* only relevant in the forked process for running the server. */
static int listener_is_running;
static int handler_is_running;

static struct sigaction server_old_sa;

static void handle_connection_stop(int s)
{
	UNUSED_VAR(s);

	printf("[*] Closing connection (server command)\n");

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

static void server_sigchld_handler(int s)
{
	UNUSED_VAR(s);

	printf("[!] Listener encountered unexpected error\n");
	wait(NULL);
}

int main(void)
{
	struct server_tcpip *server = server_tcpip_create(PORT_NUM,
							"127.0.0.1",
							10);
	if(server == NULL)
		return 0;

	print_server_tcpip_info(server);

	int pid = server_tcpip_start(server);
	if(pid == -1)
		return 0;

	getchar();
	
	server_tcpip_shutdown(pid, server);
	
	return 0;
}


static void print_server_tcpip_info(struct server_tcpip *server)
{
	printf("[*] Server Info:\n"
			"\tIP  : %s\n"
			"\tPORT: %d\n",
			inet_ntoa(server->addr.sin_addr),
			ntohs(server->addr.sin_port));
}

static struct server_tcpip *server_tcpip_init(short port,
						const char *ip)
{
	
	int err;
	struct server_tcpip *server;

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

static struct server_tcpip *server_tcpip_create(short port, 
						const char *ip,
						int backlog)
{
	struct server_tcpip *server;
	struct protoent *tcp_prot;
	int optval = 1;
	int err;

	server = server_tcpip_init(port, ip);
	if(server == NULL) {
		debug_trace();
		goto err_out;
	}

	/* man page says it can also be read from /etc/protocols */
	/* and apperently you don't free the returned pointer. */
	tcp_prot = getprotobyname("tcp");
	if(tcp_prot == NULL) {
		debug_trace_errno();
		goto err_out;
	}

	server->fd = socket(AF_INET, SOCK_STREAM, tcp_prot->p_proto);
	if(server->fd == -1) {
		debug_trace_errno();
		goto err_out;
	}	

	err = setsockopt(server->fd, SOL_SOCKET, SO_REUSEADDR, 
						&optval, sizeof(optval));


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
	
	server_tcpip_free(server);
	
	return NULL;
}

static void server_tcpip_free(struct server_tcpip *server)
{
	if(server == NULL)
		return;
	
	if(server->fd != -1)
		close(server->fd);

	free(server);
}

static void process_handle_connection(int peer_fd, struct sockaddr_in addr)
{
	struct sigaction sa;	
	int err;
	ssize_t nb_recv;
	ssize_t nb_send;

	char buf[500];
	size_t len = 500;

	printf("[*] Accepted connection from: %s\n",
			inet_ntoa(addr.sin_addr));

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

		nb_recv = recv(peer_fd, buf, len, 0);
		if(nb_recv == -1) {
			if(errno == ERESTART || errno == EINTR)
				break;
			else
				debug_trace_errno();
		}
		else if(nb_recv == 0) {
			break;
		}
		else {
			nb_send = send(peer_fd, buf, nb_recv, 0);
			if(nb_send == -1) {
				if(errno == ERESTART || errno == EINTR)
					break;
				else 
					debug_trace_errno();
			}
		}
	}
	

	close(peer_fd);
	_exit(EXIT_SUCCESS);
}

static void process_listen_inf(struct server_tcpip *server)
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
			if(errno == ERESTART || errno == EINTR)
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
			process_handle_connection(peer_fd, peer_addr);
		}
		else {
			/* I'm just accepting connections I don't care about
			 * talking to peer. */
			child_pids[num_chlds++] = pid;
			close(peer_fd);
		}
	}

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

	for(size_t i = 0; i < num_chlds; i++) {
		err = kill(child_pids[i], SIGUSR1);
		if(err == -1) {
			debug_trace_errno();
			_exit(EXIT_FAILURE);
		}
		err = waitpid(child_pids[i], NULL, 0);
		if(err == -1) {
			debug_trace_errno();
			_exit(EXIT_FAILURE);
		}
	}

	printf("here\n");

	_exit(EXIT_SUCCESS);
}

static int server_tcpip_start(struct server_tcpip *server)
{
	int pid;
	int err;
	struct sigaction sa;	

	sa.sa_handler = server_sigchld_handler;
	//sigfillset(&sa.sa_mask);
	/* so that I don't miss/ignore sigchlds */
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART;

	err = sigaction(SIGCHLD, &sa, &server_old_sa);
	if(err == -1) {
		debug_trace_errno();
		exit(EXIT_FAILURE);
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

	/* else return pid */

	return pid;
}

static int server_tcpip_shutdown(int pid, struct server_tcpip *server)
{
	int err;
	err = sigaction(SIGCHLD, &server_old_sa, NULL);
	if(err == -1) {
		debug_trace_errno();
		exit(EXIT_FAILURE);
	}


	err = kill(pid, SIGUSR1);
	if(err == -1) {
		debug_trace_errno();
		return -1;
	}
	waitpid(pid, NULL, 0);

	server_tcpip_free(server);
	return 0;
}
