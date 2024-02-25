/*
 * TCPSP example program
 *
 * forwarder.c:	accept a connection, forward to another server, then splice
 *
 * Copyright (C) 2002, Wensong Zhang <wensong@linux-vs.org>
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/poll.h>
#include <netdb.h>
#include <popt.h>

#include "tcpsp.h"


static unsigned long int get_inet_addr(char *server_string);


static int connect_server(struct sockaddr_in *servaddr)
{
	int sockfd;
	int rc;

	sockfd = socket(AF_INET, SOCK_STREAM, 0);

	rc = connect(sockfd, (struct sockaddr *)servaddr, sizeof(*servaddr));
	if (rc == -1)
		return -1;
	return sockfd;
}


int tcpsplicing(int fd1, int fd2, int n)
{
	int sockfd;
	splice_conn_t sp = {fd1, fd2, n};

	if ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) == -1)
		return -1;

	return setsockopt(sockfd, IPPROTO_IP,
			  TCPSP_SO_SET_ADD, &sp, sizeof(sp));
}


void start_forwarder(struct sockaddr_in *servaddr)
{
	struct sockaddr_in listenaddr;
	struct sockaddr_in cliaddr;
	socklen_t cliaddrlen;
	int listenfd;
	int fd1, fd2;
	int flag;
	char *buf;
	int len, n;
	struct pollfd pollinfo[2];


	len = 8192;
	buf = malloc(len);

	listenfd = socket(AF_INET, SOCK_STREAM, 0);

	memset(&listenaddr, 0, sizeof (listenaddr));
	listenaddr.sin_family = AF_INET;
	listenaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	listenaddr.sin_port = htons (8888);

	flag = 1;
	setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(flag));

	if (bind(listenfd, (struct sockaddr *)&listenaddr,
		 sizeof(listenaddr)) < 0) {
		printf("bind error.\n");
		exit(1);
	}
	if (listen(listenfd, 100) < 0) {
		printf("listen error.\n");
		exit(1);
	}

	cliaddrlen = sizeof(cliaddr);
	fd1 = accept(listenfd, (struct sockaddr *)&cliaddr, &cliaddrlen);
	if (fd1 == -1) {
		printf("accept error.\n");
		exit(1);
	}

	n = read(fd1, buf, len);
	if (n < 0 && errno == ECONNRESET) {
		close(fd1);
		exit(1);
	}
	//printf("read the request of %d bytes from sock1\n", n);

	fd2 = connect_server(servaddr);
	if (fd2 == -1) {
		printf("connect to server failed.\n");
		exit(1);
	}

	if (tcpsplicing(fd1, fd2, n))
		printf("tcpsplicing failed\n");
	else
		printf("tcpsplicing succeeded\n");

	write(fd2, buf, n);


	pollinfo[0].fd = fd1;
	pollinfo[0].events = POLLIN;
	pollinfo[0].revents = 0;

	pollinfo[1].fd = fd2;
	pollinfo[1].events = POLLIN;
	pollinfo[1].revents = 0;

	while (1) {
		int i;

		i = poll(pollinfo, 2, 1000);

		if (i > 0) {
			if (pollinfo[0].revents & POLLIN) {
				n = read(fd1, buf, len);
				if (n > 0) {
					//printf("read %d bytes from sock1 "
					//       "and write to sock2\n", n);
					write(fd2, buf, n);
				}
				else if (n == 0)
					break;
			}

			if (pollinfo[1].revents & POLLIN) {
				n = read(fd2, buf, len);
				if (n > 0) {
					//printf("read %d bytes from sock2 "
					//       "and write to sock1\n", n);
					write(fd1, buf, n);
				} else if (n == 0)
					break;
			}
		}
	}

	close(fd2);
	close(fd1);
	close(listenfd);
	free(buf);
}


int
main(int argc, char **argv)
{
	char *server_string = "localhost";
	int port = 80;
	struct sockaddr_in servaddr;

	char c;
	poptContext optCon;
	struct poptOption optionsTable[] = {
		{ "server", 's', POPT_ARG_STRING, &server_string, 0,
		  "server name", "name|IP" },
		{ "port", 'p', POPT_ARG_INT, &port, 0,
		  "server port number", "port" },
		POPT_AUTOHELP
		{ NULL, 0, 0, NULL, 0 }
	};

	optCon = poptGetContext("forwarder", argc, (const char **)argv,
				optionsTable, 0);
	while ((c = poptGetNextOpt(optCon)) >= 0);

	if (c < -1) {
		/* an error occurred during option processing */
		fprintf(stderr, "%s: %s\n",
			poptBadOption(optCon, POPT_BADOPTION_NOALIAS),
			poptStrerror(c));
		exit(1);
	}

	memset (&servaddr, 0, sizeof (servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = get_inet_addr(server_string);
	servaddr.sin_port = htons (port);

	start_forwarder(&servaddr);

	return 0;
}


static int host_to_addr(const char *name, struct in_addr *addr)
{
	struct hostent *host;

	if ((host = gethostbyname(name)) != NULL) {
		if (host->h_addrtype != AF_INET ||
		    host->h_length != sizeof(struct in_addr))
			return -1;
		/* warning: we just handle h_addr_list[0] here */
		memcpy(addr, host->h_addr_list[0], sizeof(struct in_addr));
		return 0;
	}
	return -1;
}

static unsigned long int
get_inet_addr(char *server_string)
{
	struct in_addr inaddr;

	if (inet_aton(server_string, &inaddr) != 0)
		return inaddr.s_addr;
	if (host_to_addr(server_string, &inaddr) != -1)
		return inaddr.s_addr;
	return INADDR_NONE;
}
