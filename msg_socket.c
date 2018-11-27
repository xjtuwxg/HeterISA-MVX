#include "msg_socket.h"
#include "debug.h"
int port = 8888;

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

int create_client_socket(char *ip)
{
	int clientfd;
	struct sockaddr_in serveraddr;

	/* Create a socket descriptor */
	if ((clientfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		fprintf(stderr, "create listen socket error\n");
		return -1;
	}
	memset(&serveraddr, 0, sizeof(serveraddr));
	serveraddr.sin_family = AF_INET;
	//serveraddr.sin_addr.s_addr = INADDR_ANY;
	serveraddr.sin_port = htons(port);
	if (inet_pton(AF_INET, ip, &serveraddr.sin_addr) < 0) {
		fprintf(stderr, "convert serveraddr error\n");
		return -1;
	}
	if (connect(clientfd, (SA*)&serveraddr, sizeof(serveraddr)) < 0) {
		fprintf(stderr, "connection error\n");
		return -1;
	}

	return clientfd;
}

int create_server_socket(void)
{
	int listenfd;
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

	//MSG_PRINT("%s: listenfd: %d\n", __FUNCTION__, listenfd);

	while ((connfd = accept(listenfd, &in_addr, &in_len)) != -1) {
		if (getnameinfo(&in_addr, in_len, hbuf, sizeof(hbuf), pbuf,
				sizeof(pbuf), NI_NUMERICHOST) == 0) {
			//MSG_PRINT("accept conn on fd %d, host: %s, port: %s\n",
			//       connfd, hbuf, pbuf);
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
	return 0;
}

void process_data(int fd)
{
	ssize_t cnt;
	//ssize_t msg_len = 0;
	char buf[512];

	//MSG_PRINT("Process data on fd %d\n", fd);
	cnt = read(fd, buf, sizeof(buf)-1);
	buf[cnt] = 0;
#if 0
	while ((cnt = read(fd, buf, sizeof(buf)-1))) {
		if (cnt == -1) {
			if (errno == EAGAIN) return;
			fprintf(stderr, "read error\n");
			break;
		}
		msg_len += cnt;
		MSG_PRINT("Client input: %s. cnt %u\n", buf, cnt);
	}
#endif
	//MSG_PRINT("Close conn on fd: %d\n", fd);
	close(fd);

	PRINT("msg: %s, cnt: %lu\n", buf, cnt);
	// copy data to global message
	memcpy(msg.buf, buf, cnt);
	msg.len = cnt;
	sem_post(&msg.lock);

	//sem_getvalue(&msg.lock, &cnt);
	//PRINT("sem lock %ld\n", cnt);
}

void * msg_thread_main(void *args)
{
	/* create socket and listen */
	if ((listenfd = create_server_socket()) < 0)
		abort();
	if (listen(listenfd, SOMAXCONN) < 0)
		fprintf(stderr, "listen socket error\n");

	/* create epoll */
	if ((efd = epoll_create1(0)) == -1) {
		FATAL("epoll create error");
	}
	event.data.fd = listenfd;
	event.events = EPOLLIN | EPOLLET;
	//event.events = EPOLLIN;
	if (epoll_ctl(efd, EPOLL_CTL_ADD, listenfd, &event) < 0)
		fprintf(stderr, "epoll ctr error\n");
	//MSG_PRINT("listenfd: %d, efd: %d. MAXEVENTS %d\n",
	//       listenfd, efd, MAXEVENTS);

	while (1) {
		int nfds, i;
		/* nfds, events are output values */
		nfds = epoll_wait(efd, events, MAXEVENTS, -1);
		//MSG_PRINT("# of events(fds): %d\n", nfds);

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
}

void msg_thread_init(void)
{
	pthread_t tid;

	// init the global message msg.
	memset(msg.buf, 0, sizeof(msg.buf));
	sem_init(&msg.lock, 0, 0);

	// create the messaging thread.
	if (pthread_create(&tid, NULL, msg_thread_main, NULL)) {
		FATAL("pthread create failed\n");
	}
	//PRINT("%s should never return!\n", __func__);
	PRINT("pthread created\n");
}

void msg_wait_recv(msg_t *msg)
{
	sem_wait(&msg->lock);
}

