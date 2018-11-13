#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <netdb.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>

#define MAXEVENTS 64
int port = 8888;
typedef struct sockaddr SA;

static int make_socket_non_blocking(int sfd)
{
	int flags;

	flags = fcntl(sfd, F_GETFL, 0);
	if (flags == -1) {
		perror("fcntl");
		return -1;
	}

	flags |= O_NONBLOCK;
	if (fcntl(sfd, F_SETFL, flags) == -1) {
		perror("fcntl");
		return -1;
	}

	return 0;
}

static int create_socket(void)
{
	int listenfd, flags;
	struct sockaddr_in serveraddr;
	int opt = 1;

	/* Create a socket descriptor */
	if ((listenfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		fprintf(stderr, "create listen socket error\n");
		return -1;
	}

	/* setsockopt */
	if (setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &opt,
					sizeof(int)) == -1) {
            perror("Setsockopt");
            exit(1);
        }

	/* Listenfd will be an endpoint for all requests to port
	   on any IP address for this host */
	memset(&serveraddr, 0, sizeof(serveraddr));
	serveraddr.sin_family = AF_INET;
	serveraddr.sin_addr.s_addr = INADDR_ANY;
	serveraddr.sin_port = htons(port);

	if (bind(listenfd, (SA *)&serveraddr, sizeof(SA)) < 0) {
		fprintf(stderr, "bind error\n");
		return -1;
	}

	/* make socket non blocking ?? */
	if (make_socket_non_blocking(listenfd) == -1)
		return -1;

	return listenfd;
}

static int accept_connection(int listenfd, int epollfd)
{
	int connfd;
	SA in_addr;
	socklen_t in_len = sizeof(in_addr);
	char hbuf[NI_MAXHOST], pbuf[NI_MAXSERV];
	struct epoll_event event;

	printf("%s: listenfd: %d\n", __FUNCTION__, listenfd);

	while ((connfd = accept(listenfd, &in_addr, &in_len)) != -1) {
		if (getnameinfo(&in_addr, in_len, hbuf, sizeof(hbuf), pbuf,
				sizeof(pbuf), NI_NUMERICHOST) == 0) {
			printf("accept conn on fd %d, host: %s, port: %s\n",
			       connfd, hbuf, pbuf);
		}
		/* non blocking socket */
		if (make_socket_non_blocking(connfd) == -1) {
			abort();
		}
		/* add the conn socket to epoll monitor */
		event.data.fd = connfd;
		event.events = EPOLLIN | EPOLLET;
		if (epoll_ctl(epollfd, EPOLL_CTL_ADD, connfd, &event) == -1) {
			fprintf(stderr, "epoll ctl error\n");
			return -1;
		}
		in_len = sizeof(in_addr);
	}
}

void process_data(int fd)
{
	ssize_t cnt;
	char buf[512];

	printf("\nProcess data on fd %d\n", fd);

	while ((cnt = read(fd, buf, sizeof(buf)-1))) {
		if (cnt == -1) {
			if (errno = EAGAIN) return;
			fprintf(stderr, "read error\n");
			break;
		}
		buf[cnt] = 0;
		printf("Client input: %s", buf);
	}
	printf("Close conn on fd: %d\n", fd);
	close(fd);
}

int main(int argc, char *argv[])
{
	struct epoll_event event;
	struct epoll_event events[MAXEVENTS];
	int listenfd, efd;
	int ret = 0;

	/* create socket and listen */
	if ((listenfd = create_socket()) < 0)
		abort();

	if (listen(listenfd, SOMAXCONN) < 0)
		fprintf(stderr, "listen socket error\n");

	/* create epoll */
	efd = epoll_create1(0);

	event.data.fd = listenfd;
	event.events = EPOLLIN | EPOLLET;
	//event.events = EPOLLIN;

	if (epoll_ctl(efd, EPOLL_CTL_ADD, listenfd, &event) < 0)
		fprintf(stderr, "epoll ctr error\n");

	printf("listenfd: %d, efd: %d. MAXEVENTS %d\n",
	       listenfd, efd, MAXEVENTS);

	while (1) {
		int nfds, i;
		/* nfds, events are output values */
		nfds = epoll_wait(efd, events, MAXEVENTS, -1);
		printf("# of events(fds): %d\n", nfds);

		for (i = 0; i < nfds; i++) {
			if (listenfd == events[i].data.fd) {
				/* Accept new incoming connection */
				accept_connection(listenfd, efd);
			} else if (events[i].events & EPOLLERR ||
				   events[i].events & EPOLLHUP ||
				   !(events[i].events & EPOLLIN)) {
				fprintf(stderr, "epoll error\n");
				close(events[i].data.fd);
			} else {
				/* process data processing on fd */
				process_data(events[i].data.fd);
			}
		}
	}

	close(listenfd);

	return 0;
}
