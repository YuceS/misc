/*
 * Transparent TCP port-forwarding over SOCKS5 using firewall next-hop rewrites
 * Based on an idea from http://transocks.sourceforge.net/
 *      -- noah@hack.se, 2009
 *
 * Written because running TCP/IP over TCP/IP on 3G, using ssh+slirp, ssh+pppd
 * or simply openvpn, over the existing 3G-connection was slow as fuck.
 * Throughput was about 10-15 times slower compared to running natively.
 * (No surprise here, it just sucks really bad.)
 *
 *
 * This program relies on Linux and BSD firewalls' ability to multiplex outgoing
 * connections to a different port while still providing means of reading out
 * the original destination address.
 *  
 * On Linux this can be achieved using iptables' REDIRECT-target to multiplex
 * outgoing TCP-connections to a different port. The original destination 
 * address can be read out using the SO_ORIGINAL_DST option at the SOL_IP
 * level with getsockopt(2) on Linux 2.4/2.6.
 * 
 * On FreeBSD and Mac OS X similar functionality is provided by the fwd action
 * in IPFW. The original destination address can be read out using a simple
 * getsockname() on the socket returned by accept(2).
 *
 *
 * Here's an example on Linux, assuming only port 8080 is open to the world.
 * We'll be using SSH to connect to a remote server on port 8080 and then let
 * SSH provide a local SOCKS5 server using option -D (DynamicForward)
 *
 * # Setup an SSH-session that provides dynamic port-forwarding (SOCKS5) on
 *   port 1080. Also, fork into the background after login (-Nf)
 *   $ ssh -p8080 -D 1080 -Nf user@example.net
 *
 * # Setup the multiplexor service, waiting for multiplexed connections on
 *   port 1081, forwarding them to the SOCKS5 server on port 1080 (SSH)
 *   $ ./fw-socks5-fwd -f -p 1211 -s 1080
 *
 * # Setup iptables to forward all outgoing connections to port 1081
 *   where this program is listening
 *   # iptables -t nat -A OUTPUT -p tcp --syn -d 127.0.0.0/8 -j RETURN
 *   # iptables -t nat -A OUTPUT -p tcp -j REDIRECT --to-port 1211
 *
 * This currently suggested iptables rules will only work for locally
 * initiated TCP-connections. It will not work for NAT'ed machines'
 * connections if this machine is acting as a router.
 *
 *
 * Tested on Linux 2.6.28 (Ubuntu) and Mac OS X Leopard
 * Compile:
 *   $ gcc -o fw-socks5-fwd fw-socks5-fwd.c -Wall
 *
 * References:
 * http://www.ietf.org/rfc/rfc1928.txt (SOCKS Protocol Version 5)
 * http://transocks.sourceforge.net/ (first released 1999)
 *
 *
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <errno.h>
#include <syslog.h>
#include <signal.h>

#ifdef __linux__
#include <limits.h>
/* ..for SO_ORIGINAL_DST option to getsockopt() */
#include <linux/netfilter_ipv4.h>
#endif


struct queue {
	char buf[32*1024];
	int len;
};

struct fwd {
	/* Local (incoming) fd and read queue */
	int local_fd;
	struct queue *local_rq;

	/* Remote (to multiplexed service) fd and read queue */
	int remote_fd;
	struct queue *remote_rq;

	/* Destination address for remote connection */
	struct sockaddr_in sin_dst;

	/* State */
	int state;

	/* Time of last I/O */
	time_t timestamp;
};

enum service_type {
	/* Client sends "SSH-" */
	SERVICE_SSH,
	/* Client sends "GET ", "POST ", "PUT ", .. */
	SERVICE_HTTP,
	/* Client sends SSL Hello message */
	SERVICE_SSL,
	/* Client sends SOCKS5 request */
	SERVICE_SOCKS5
	/* Original destination is forwarded through SOCKS5 */
	SERVICE_TSOCKS
};

struct service {
	enum service_type type;
	struct sockaddr_in sin;
};


enum queue_id {
	LOCAL_READ_QUEUE,
	REMOTE_READ_QUEUE
};


int setup_listening_port(int);
int the_infinite_loop(int);
int accept_multiplexed_connection(int);
int process_socks5_state(struct fwd *);
struct service *service_register(enum service_type type, struct sockaddr_in *sin);
struct service_ *service_find(enum service_type type);
void fwd_free(struct fwd *);
int block_write(int, void *, int);
int read_to_queue(struct fwd *, enum queue_id);
int drain_queue_to_fd(struct fwd *, enum queue_id);
void sighandler(int);


/* Address and port for the SOCKS5 server */
struct sockaddr_in sin_socks;

/* List of services */
struct service **service_list;
int num_services;

/* List of forwarded connections */
struct fwd **fwd_list;
int num_fwds;

/* Default options */
char *opt_pid_path = "/var/run/fw-socks5-fwd.pid";
int opt_multiplex_port = 1211;


int main(int argc, char **argv) {
	int accept_fd, ch;
	struct sockaddr_in sin;
	int opt_usage = 0;
	int opt_daemonize = 1;
	char *port = "1080";
	FILE *fd;


	printf("Transparent TCP port-forwarding over SOCKS5 using firewall next-hop rewrites\n"
		"   -- noah@hack.se, 2009\n\n");

	while((ch = getopt(argc, argv, "fp:s:")) != -1) {
		switch(ch) {
		case 'f':
			opt_daemonize = 0;
			break;

		case 'p':
			if((opt_multiplex_port = atoi(optarg)) <= 0) {
				fprintf(stderr, "ERROR: Invalid multiplex port '%s'\n", optarg);
				exit(EXIT_FAILURE);
			}
			break;

		case 's':
			port = strchr(optarg, ':');
			if(port == NULL || *++port == 0 || atoi(port) < 1) {
				fprintf(stderr, "ERROR: Invalid service format or port\n");
				exit(EXIT_FAILURE);
			}

			memset(&sin_socks, 0, sizeof(sin));
			sin_socks.sin_family = PF_INET;
			sin_socks.sin_addr.s_addr = inet_addr("127.0.0.1");
			sin_socks.sin_port = htons(atoi(port));

			if(!strcmp(optarg, "http"))
				service_register(SERVICE_HTTP, &sin);
			else if(!strcmp(optarg, "socks5"))
				service_register(SERVICE_SOCKS5, &sin);
			else if(!strcmp(optarg, "ssh"))
				service_register(SERVICE_SSH, &sin);
			else if(!strcmp(optarg, "ssl"))
				service_register(SERVICE_SSL, &sin);
			else if(!strcmp(optarg, "tsocks"))
				service_register(SERVICE_TSOCKS, &sin);
			else {
				fprintf(stderr, "ERROR: Unsupported service '%s'\n", optarg);
				exit(EXIT_FAILURE);
			}

			break;

		case 'P':
			opt_pid_path = strdup(optarg);
			break;

		case '?':
			opt_usage++;
			break;
		}
	}


	if(argc == 1 || opt_usage || num_services == 0) {
		printf(	"Usage: %s -s <http|ssh|ssl|socks5|tsocks>:<port> [-f] [-p port] [-P my.pid]\n"
			"  -f               Run in the foreground (useful for debugging)\n"
			"  -p port          Port to accept multiplexed connections on (default: 1211)\n"
			"  -s service:port  Service and port <socks5\n"
			"  -P file          Path to PID-file (default: /var/run/fw-socks5-fwd.pid)\n"
			"NOTE: This program assumes the SOCKS5 server is listening on 127.0.0.1\n\n",
			argv[0]);

		return 0;
	}


	/* Setup a port we'll listen for multiplexed connections on */
	if((accept_fd = setup_listening_port(opt_multiplex_port)) == -1)
		return -1;


	printf(	"* Listening for multiplexed connections on local port %d\n"
		"* Connections will be forwarded to SOCKS5 server at 127.0.0.1:%s\n"
#ifdef __linux__
		"* Now, make iptables multiplex outgoing connections to this program using\n"
		"  # iptables -t nat -A OUTPUT -p tcp --syn -d 127.0.0.0/8 -j RETURN\n"
		"  # iptables -t nat -A OUTPUT -p tcp --syn -j REDIRECT --to-port %d\n",
#else
		"* Now, make ipfw multiplex outgoing connections to this program using\n"
		"  # ipfw add check-state\n"
		"  # ipfw add allow tcp from me to 127.0.0.0/8 setup keep-state\n"
		"  # ipfw add fwd 127.0.0.1,%d tcp from me to any setup keep-state\n",
#endif
		opt_multiplex_port, port, opt_multiplex_port);


	if(opt_daemonize) {
		daemon(0, 0);
		
		if((fd = fopen(opt_pid_path, "w")) != NULL) {
			fprintf(fd, "%d", getpid());
			fclose(fd);
		}
	}


	/* Exit cleanly when interrupted */
	signal(SIGHUP, sighandler);
	signal(SIGINT, sighandler);
	signal(SIGTERM, sighandler);

	openlog("fw-socks5-fwd", (!opt_daemonize? LOG_PERROR: 0), LOG_DAEMON);
	syslog(LOG_INFO, "Listening for multiplexed connections on local port %d",  opt_multiplex_port);
	for(ch = 0; ch < num_services; ch++) 
		syslog(LOG_INFO, "Forwarding %s connections to 127.0.0.1:%d", 
		       service_list[ch]->type == SERVICE_SSH? "SSH":
		       service_list[ch]->type == SERVICE_SSL? "SSL":
		       service_list[ch]->type == SERVICE_HTTP? "HTTP":
		       service_list[ch]->type == SERVICE_SOCKS5? "SOCKS5": "",
		       ntohs(service_list[ch]->sin.sin_port));


	return the_infinite_loop(accept_fd);
}


int setup_listening_port(int port) {
	int fd, flags;
	struct sockaddr_in sin;

	if((fd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
		perror("socket()");
		return -1;
	}

	flags = fcntl(fd, F_GETFL, 0);
	if(flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
		perror("fcntl()");
		close(fd);
		return -1;
	}

	flags = 1;
	if(setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (void *)&flags, sizeof(flags))) {
		syslog(LOG_NOTICE, "setsockopt(SO_REUSEADDR) on listen socket failed with error %d (%s)\n",
			errno, strerror(errno));
	}


	memset(&sin, 0, sizeof(sin));
	sin.sin_family = PF_INET;
	sin.sin_port = htons(port);
	if((bind(fd, (struct sockaddr *)&sin, sizeof(sin))) < 0) {
		syslog(LOG_NOTICE, "Failed to setup listening port, bind() failed with error %d (%s)\n",
			errno, strerror(errno));
		close(fd);
		return -1;
	}
	else if(listen(fd, 10) < 0) {
		syslog(LOG_NOTICE, "Failed to setup listening port, listen() failed with error %d (%s)\n",
			errno, strerror(errno));
		close(fd);
		return -1;
	}

	return fd;
}


int the_infinite_loop(int accept_fd) {
	int i;
	int max_fd, ret;
	struct fwd *f;
	fd_set rfds, wfds;
	time_t timestamp;

	for(;;) {
		FD_ZERO(&rfds);
		FD_ZERO(&wfds);

		FD_SET(accept_fd, &rfds);

		max_fd = accept_fd;
		for(i = 0; i < num_fwds; i++) {
			f = fwd_list[i];

			if(f->remote_fd > max_fd)
				 max_fd = f->remote_fd;

			if(f->local_fd > max_fd)
				 max_fd = f->local_fd;

			FD_SET(f->local_fd, &rfds);
			if(f->remote_rq->len && f->state == 4 /* only care when not negotiating SOCKS5 */)
				FD_SET(f->local_fd, &wfds);

			if(f->remote_fd >= 0) {
				FD_SET(f->remote_fd, &rfds);
				if(f->local_rq->len || f->state == 0 /* to catch connect() errors */)
					FD_SET(f->remote_fd, &wfds);
			}
		}

		if((ret = select(max_fd + 1, &rfds, &wfds, NULL, NULL)) < 0)
			break;


		/* Accept new connection */
		if(FD_ISSET(accept_fd, &rfds)) {
			accept_multiplexed_connection(accept_fd);
			if(ret == 1)
				continue;
		}


		/* Loop trough all connections in SOCKS5 negotiation mode (state 0-3) */
		for(i = 0; i < num_fwds; i++) {
			f = fwd_list[i];

			/* Skip connections in data-exchanging state */
			if(f->state == 4)
				continue;

			/* Queue incoming data from client */
			if(FD_ISSET(f->local_fd, &rfds) && read_to_queue(f, LOCAL_READ_QUEUE) < 0)
				break;

			/* Queue incoming data from remote service */
			if(f->remote_fd >= 0 && FD_ISSET(f->remote_fd, &rfds) && read_to_queue(f, REMOTE_READ_QUEUE))
				break;

			/* Attempt to identify client protocol */
			if(f->local_rq->len && identify_protocol(f) < 0)
				break;

			/* 
			if((f->state == 0 && FD_ISSET(f->remote_fd, &wfds)) || f->remote_rq->len)
				if(process_socks5_state(f))
					break;
			 */
		}


		/* Get current time once */
		timestamp = time(NULL);
		
		
		/* Do a second pass and shuffle data between the peers */
		for(i = 0; i < num_fwds; i++) {
			f = fwd_list[i];

			/* Skip connections where SOCKS5 negotiation hasn't completed yet */
			if(f->state != 4)
				continue;

			/* Read data from one peer and drain it onto the other */
			if(FD_ISSET(f->local_fd, &rfds) && read_to_queue(f, LOCAL_READ_QUEUE) < 0)
				break;

			if(f->local_rq->len && drain_queue_to_fd(f, LOCAL_READ_QUEUE) < 0)
				break;

			if(FD_ISSET(f->remote_fd, &rfds) && read_to_queue(f, REMOTE_READ_QUEUE) < 0)
				break;

			if(f->remote_rq->len && drain_queue_to_fd(f, REMOTE_READ_QUEUE) < 0)
				break;

			f->timestamp = timestamp;
		}
	}

	return 0;
}


int accept_multiplexed_connection(int accept_fd) {
	struct sockaddr_in sin;
	socklen_t sinlen;
	int flags;
	struct fwd *f;
	struct service *service;

	f = (struct fwd *)malloc(sizeof(struct fwd));
	if(f == NULL)
		return 0;
	
	f->local_rq = NULL;
	f->remote_rq = NULL;
	f->state = 0;
	f->local_fd = local_fd;
	f->remote_fd = -1;
	f->timestamp = time(NULL);

	
	memset(&sin, 0, sizeof(sin));
	sinlen = sizeof(sin);
	if((f->local_fd = accept(accept_fd, (struct sockaddr *)&sin, &sinlen)) < 0) {
		syslog(LOG_NOTICE, "Failed to accept client, accept() failed with error %d (%s)\n",
			errno, strerror(errno));
		fwd_free(f);
		return -1;
	}

	syslog(LOG_DEBUG, "%d: ACCEPT: New connection from %s:%d\n",
		f->local_fd, inet_ntoa(sin.sin_addr), ntohs(sin.sin_port));


	/* Make client socket nonblocking */
	flags = fcntl(f->local_fd, F_GETFL, 0);
	if(flags < 0 || fcntl(f->local_fd, F_SETFL, flags | O_NONBLOCK) < 0) {
		fwd_free(f);
		return -1;
	}
	
	
	sin_len = sizeof(struct sockaddr_in);
#ifdef __linux__
	/* Get original destination address on Linux 2.6 */
	if(getsockopt(f->local_fd, SOL_IP, SO_ORIGINAL_DST, (struct sockaddr *)&f->sin_dst, &sinlen)) {
		syslog(LOG_NOTICE, "Failed to get original destination address, "
			"getsockopt(.., SOL_IP, SO_ORIGINAL_DST, ..) failed with error %d (%s)\n",
			errno, strerror(errno));

		fwd_free(f);
		return -1;
	}
#else
	/* This is how it's done on FreeBSD, Mac OS X and Linux 2.2 */
	if(getsockname(f->local_fd, (struct sockaddr *)&f->sin_dst, &sinlen)) {
		syslog(LOG_NOTICE, "Failed to get original destination address, "
			"getsockname() failed with error %d (%s)\n", errno, strerror(errno));
		fwd_free(f);
		return -1;
	}
#endif

	
	/* Special case for transparent connections */
	if(getsockname(accept_fd, (struct sockaddr *)&sin, &sinlen) < 0) {
		syslog(LOG_NOTICE, "Failed to get local address, "
		       "getsockname() failed with error %d (%s)\n", errno, strerror(errno));
		fwd_free(f);
		return -1;
	}
	
	if(f->sin_dst.sin_addr.s_addr != sin.sin_addr.s_addr
	   || f->sin_dst.sin_port != sin.sin_port) {
		syslog(LOG_DEBUG, "%d: ACCEPT: Original destination is %s:%d\n",
		       f->local_fd, inet_ntoa(f->dst_sin.sin_addr), ntohs(f->dst_sin.sin_port));

		service = service_find(SERVICE_TSOCKS);
		if(service == NULL) {
			syslog(LOG_NOTICE, "%d: ACCEPT: No TSOCKS service defined", f->local_fd);
			fwd_free(f);
			return -1;
		}
		
		/* Hook up with the SOCKS5 server */
		if((f->remote_fd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
			fwd_free(f);
			return -1;
		}
		
		flags = fcntl(f->remote_fd, F_GETFL, 0);
		if(flags < 0 || fcntl(f->remote_fd, F_SETFL, flags | O_NONBLOCK) < 0) {
			fwd_free(f);
			return -1;
		}
		
		if(connect(f->remote_fd, (struct sockaddr *)&service->sin, sizeof(service->sin)) < 0
		   && errno != EINPROGRESS && errno != EINTR) {
			syslog(LOG_DEBUG, "%d: TSOCKS: Connect to SOCKS5 server failed with error %d (%s)\n",
			       f->local_fd, errno, strerror(errno));
			
			fwd_free(f);
			return -1;
		}
	}
	else
		memset(&f->sin_dst, 0, sizeof(struct sockaddr_in));
	

	
	/* Allocate I/O buffers */
	if((f->local_rq = (struct queue *)malloc(sizeof(struct queue))) == NULL
	   || (f->remote_rq = (struct queue *)malloc(sizeof(struct queue))) == NULL) {
		fwd_free(f);
		return -1;
	}
	
	f->local_rq->len = 0;
	f->remote_rq->len = 0;
	
	
	/* Add client to list of forwarded connections */
	fwd_list = (struct fwd **)realloc(fwd_list, (num_fwds + 1) * sizeof(struct fwd *));
	if(fwd_list == NULL)
		exit(EXIT_FAILURE);
	
	fwd_list[num_fwds++] = f;
	

	return 0;
}


int identify_protocol(struct fwd *f) {
	struct service *service;
	unsigned int value;
	
	/* Deal with transparent connections */
	if(f->sin_dst.sin_len != 0)
		return process_tsocks_state(f);

	service = NULL;
	/* Try HTTP */
	if(f->local_rq->len >= 18 && 
	   (!strcasecmp("GET ", f->local_rq->buf)
	    || !strcasecmp("POST ", f->local_rq->buf))
	    || !strcasecmp("HEAD ", f->local_rq->buf))
	    || !strcasecmp("PUT ", f->local_rq->buf)))
		service = service_find(SERVICE_HTTP);
	/* Try SSL: */
	else if(f->local_rq->len >= 5) {
		value = (f->local_rq->buf[3] << 8) | f->local_rq->buf[4];
		if(f->local_rq->buf[0] == 0x16 && f->local_rq->buf[1] == 3 && value < f->local_rq->len)
			service = service_find(SERVICE_SSL);
	}
	/* Try: SOCKS5 */
	else if(f->local_rq->len >= 3 && f->local_rq->buf[0] == 5 && f->local_rq->buf[1] > 0) {
		if(f->local_rq->buf[1] == 2 + f->local_rq->len)
			service = service_find(SERVICE_SOCKS5);
	}
	/* Fallback on SSH if more than 5 seconds have passed */
	else if(f->local_rq->len == 0 && f->timestamp + 5 < time(NULL))
		service = service_find(SERVICE_SSH);


	if(!service)
		return NULL;

	if(service == NULL && t->timestamp + 10 < time(NULL)) {
		/* Failed to identify service */
		fwd_free(f);
		return -1;
	}
		
	if(service) {
		
	}
	
}


/* Shutdown a forwarded connection. Called by any function that encounters an error. */
void fwd_free(struct fwd *f) {
	int i;
	
	syslog(LOG_DEBUG, "%d: CLOSE: Removing connection to %s:%d on remote fd %d\n",
	       f->local_fd, inet_ntoa(f->sin_dst.sin_addr), ntohs(f->sin_dst.sin_port), f->remote_fd);
	
	close(f->local_fd);
	if(f->remote_fd != -1)
		close(f->remote_fd);
	
	if(f->local_rq)
		free(f->local_rq);
	
	if(f->remote_rq)
		free(f->remote_rq);
	
	for(i = 0; i < num_fwds; i++) {
		if(fwd_list[i] != f)
			continue;
		
		free(f);
		fwd_list[i] = fwd_list[--num_fwds];
		
		fwd_list = (struct fwd **)realloc(fwd_list, num_fwds * sizeof(struct fwd *));
		if(num_fwds && fwd_list == NULL)
			exit(EXIT_FAILURE);
		
		return;
	}
	
}


/* Process state for a transparent SOCKS5 connection */
int process_tsocks_state(struct fwd *f) {
	char buf[10];
	int flags, ret, value;
	socklen_t valuesize;

	
	ret = 0;
	switch(f->state) {
	case 0:
		valuesize = sizeof(value);
		if((ret = getsockopt(f->remote_fd, SOL_SOCKET, SO_ERROR, (void *)&value, &valuesize)) < 0) {
			syslog(LOG_DEBUG, "%d: SOCKS5: getsockopt(SOL_SOCKET, SO_ERROR) failed with errno %d (%s)\n",
				f->local_fd, errno, strerror(errno));
			break;
		}

		if(value) {
			syslog(LOG_DEBUG, "%d: SOCKS5: Connect to SOCKS5 server failed with error %d (%s)\n",
				f->local_fd, value, strerror(value));
			ret = -1;
			break;
		}

		syslog(LOG_DEBUG, "%d: SOCKS5: Connected to SOCKS5 server at %s:%d\n",
			f->local_fd, inet_ntoa(sin_socks.sin_addr), ntohs(sin_socks.sin_port));

		/* socket connected() */
		f->state++;

	case 1:
		/* Request access with method 'No Authentication' */
		buf[0] = 0x05;	/* SOCKS version 5 */
		buf[1] = 1;	/* Number of methods */
		buf[2] = 0;	/* Method: No auth */
		if((ret = block_write(f->remote_fd, buf, 3)) < 0)
			syslog(LOG_DEBUG, "%d: SOCKS5: Failed to send method list\n", f->local_fd);

		f->state++;
		break;

	case 2:
		if(f->remote_rq->len < 2)
			break;

		memcpy(buf, f->remote_rq->buf, 2);
		if((f->remote_rq->len -= 2) > 0)
			memmove(f->remote_rq->buf, f->remote_rq->buf + 2, f->remote_rq->len);

		/* Verify that we're indeed talking SOCKS5 and that
		   the server accepted our "no auth" method (0) */
		if(buf[0] != 0x05 || buf[1] != 0) {
			syslog(LOG_DEBUG, "%d: SOCKS5: Unexpected auth response: version=%d, method=%d\n",
				f->local_fd, buf[0], buf[1]);
			ret = -1;
			break;
		}



		/* Request CONNECT to the real destination address */
		buf[0] = 0x05;	/* SOCKS version 5 */
		buf[1] = 0x01;	/* Command CONNECT */
		buf[2] = 0x00;	/* Reserved */
		buf[3] = 0x01;	/* Address type: IPV4 */
		memcpy(buf + 4, &f->sin_dst.sin_addr.s_addr, 4);
		memcpy(buf + 8, &f->sin_dst.sin_port, 2);
		if((ret = block_write(f->remote_fd, buf, 10)) < 0)
			syslog(LOG_DEBUG, "%d: SOCKS5: Failed to send CONNECT request\n", f->local_fd);
		else
			syslog(LOG_DEBUG, "%d: SOCKS5: Sent CONNECT request to %s:%d\n",
				f->local_fd, inet_ntoa(f->sin_dst.sin_addr), ntohs(f->sin_dst.sin_port));

		f->state++;
		break;

	case 3:
		if(f->remote_rq->len < 10)
			break;

		memcpy(buf, f->remote_rq->buf, 10);
		if((f->remote_rq->len -= 10) > 0)
			memmove(f->remote_rq->buf, f->remote_rq->buf + 10, f->remote_rq->len);

		/* Verify response */
		if(buf[0] != 0x05	/* SOCKS version 5 */
			|| buf[1] != 0x0 /* success */
			|| buf[2] != 0x0 /* reserved */
			|| buf[3] != 0x1 /* address type IPv4 */) {
			syslog(LOG_DEBUG, "%d: SOCKS5: Unexpected CONNECT response: version=%d, success=%d (should be 0), rsvd=%d\n",
				f->local_fd, buf[0], buf[1], buf[2]);
			ret = -1;
		}
		else
			syslog(LOG_DEBUG, "%d: SOCKS5: Negotiation done, connected to remote host at %s:%d\n",
				f->local_fd, inet_ntoa(f->sin_dst.sin_addr), ntohs(f->sin_dst.sin_port));

		f->state++;
		break;
	}

	if(ret < 0)
		fwd_free(f);

	return ret;
}


struct service *service_register(enum service_type type, struct sockaddr_in *sin) {
	struct service *s;
	
	s = (struct service *)malloc(sizeof(struct service));
	if(s == NULL)
		return NULL;
	
	s->type = type;
	memcpy(&s->sin, sin, sizeof(struct sockaddr_in));

	service_list = (struct service **)realloc(service_list, (num_services + 1) * sizeof(struct service *));
	if(service_list == NULL)
		exit(EXIT_FAILURE);
	
	service_list[num_services++] = s;
	
	return s;
}


struct service_ *service_find(enum service_type type) {
	int i;
	struct service *s;
	
	for(i = 0; i < num_services; i++)
		if(service_list[i]->type == type)
			return service_list[i];

	return NULL;
}


/* Blocking read of SOCKS5 responses */
int block_write(int fd, void *data, int len) {
	char *ptr;
	int ret, retries;

	ptr = (char *)data;
	retries = 0;
	while(len && retries < 5) {
		ret = write(fd, ptr, len);
		if(ret == -1 && (errno == EINTR || errno == EAGAIN)) {
			sleep(1);
			retries++;
			continue;
		}
		else if(ret <= 0)
			return -1;

		ptr += ret;
		len -= ret;
	} while(len);

	return 0;
}


/* Read from socket and store in a buffer */
int read_to_queue(struct fwd *f, enum queue_id id) {
	int avail, fd, ret;
	struct queue *q;

	q = (id == LOCAL_READ_QUEUE? f->local_rq: f->remote_rq);
	fd = (id == LOCAL_READ_QUEUE? f->local_fd: f->remote_fd);

	avail = (int)sizeof(q->buf) - q->len;
	while(avail) {
		if((ret = read(fd, q->buf + q->len, avail)) > 0) {
			q->len += ret;
			if(ret < avail)
				break;

			avail -= ret;
			continue;
		}
		else if(ret < 0 && (errno == EINTR || errno == EAGAIN))
			break;

		syslog(LOG_DEBUG, "%d: QUEUE: read() on fd %d failed (return value was %d)\n",
			f->local_fd, fd, ret);
		fwd_free(f);
		return -1;
	}

	return 0;
}


/* Write data read from one peer to the other */
int drain_queue_to_fd(struct fwd *f, enum queue_id id) {
	int fd, offset, ret;
	struct queue *q;

	q = (id == LOCAL_READ_QUEUE? f->local_rq: f->remote_rq);
	fd = (id == LOCAL_READ_QUEUE? f->remote_fd: f->local_fd);

	offset = 0;
	while(q->len) {
		if((ret = write(fd, q->buf + offset, q->len)) > 0) {
			offset += ret;
			q->len -= ret;
			continue;
		}
		else if(ret < 0 && (errno == EINTR || errno == EAGAIN))
			break;

		syslog(LOG_DEBUG, "%d: QUEUE: write() on fd %d failed, wrote %d of %d bytes, errno is %d (%s)\n",
			f->local_fd, fd, offset, q->len + offset, errno, strerror(errno));
		fwd_free(f);
		return -1;
	}

	if(q->len)
		memmove(q->buf, q->buf + offset, q->len);

	return 0;
}


/* Exit cleanly */
void sighandler(int signo) {
	int i;

	syslog(LOG_INFO, "Got signal %d, exiting...", signo);

	for(i = num_fwds - 1; i >= 0; i--)
		fwd_free(fwd_list[i]);

	closelog();
	unlink(opt_pid_path);
}
