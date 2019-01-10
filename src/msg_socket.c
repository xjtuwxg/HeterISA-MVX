#include "msg_socket.h"
#include "debug.h"

int port = 8888;

/* ============== Ring buffer related =============== */
/**
 * Create a new ring buffer data structure pointer.
 * */
ringbuf_t ringbuf_new(void)
{
	ringbuf_t rb = malloc(sizeof(struct ringbuf_t));
	if (rb) {
		memset(rb->msg, 0, sizeof(msg_t *)*MAX_RINGBUF_SIZE);
		rb->head = rb->tail = 0;
		rb->size = 0;
		sem_init(&rb->sem, 0, 0);
		return rb;
	}
	return 0;
}

/**
 * Add msg to the ringbuf rb.
 * */
int ringbuf_add(ringbuf_t rb, msg_t *msg)
{
	if (rb->size >= MAX_RINGBUF_SIZE) return -1;

	/* Fill the ringbuf */
	rb->msg[rb->head] = msg;
	/* Advance the head indexa*/
	if (rb->head == MAX_RINGBUF_SIZE-1) rb->head = 0;
	else rb->head++;
	/* Increase the size */
	rb->size++;

	/* WARN: This operation increase the global semaphore. To work
	 * correctly, call sem_wait first before calling ringbuf_pop() */
	sem_post(&rb->sem);

	return 0;
}

/**
 * Pop (delete) msg from the ringbuf rb.
 * */
int ringbuf_pop(ringbuf_t rb, msg_t *msg)
{
	msg_t *del_msg;

	if (rb->size == 0) return -1;

	/* Retrive the msg value from ringbuf, and copy to the param msg. */
	del_msg = rb->msg[rb->tail];
	memcpy(msg, del_msg, del_msg->len + 16);
	/* Advance the tail index */
	if (rb->tail == MAX_RINGBUF_SIZE-1) rb->tail = 0;
	else rb->tail++;
	/* Decrease the size */
	rb->size--;

	/* Remove the allocated memory */
	MSG_PRINT("** after pop tail %lu (syscall %u), new tail %lu\n",
	      rb->tail-1, del_msg->syscall, rb->tail);
	free(del_msg);

	return 0;
}


/* ============== Socket related =============== */
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

	while ((connfd = accept(listenfd, &in_addr, &in_len)) != -1) {
		/* non blocking socket */
		if (make_socket_non_blocking(connfd) == -1) {
			abort();
		}
		/* add the conn socket to epoll monitor */
		event.data.fd = connfd;
		//event.events = EPOLLIN | EPOLLET;
		event.events = EPOLLIN;
		if (epoll_ctl(epollfd, EPOLL_CTL_ADD, connfd, &event) == -1) {
			fprintf(stderr, "epoll ctl error\n");
			return -1;
		}
		in_len = sizeof(in_addr);
	}
	return 0;
}

/**
 * Data processing function.
 * Copy the incoming data into the ring buffer.
 * */
void process_data(int fd)
{
	ssize_t cnt;
	char buf[512];
	// malloc in this func but not free here, delete in "ringbuf_pop"
	msg_t *new_msg = malloc(sizeof(msg_t));

	/* Read the msg_t from socket fd: read 16 bytes header first, then
	 * read the message buffer of len */
	cnt = read(fd, buf, 16);
	memcpy(new_msg, buf, 16);
	//MSG_PRINT("%s:%d syscall %d, len %u, flag %d, ret 0x%lx\n",
	//	  __FILE__, __LINE__, new_msg->syscall, new_msg->len,
	//	  new_msg->flag, new_msg->retval);

	if (new_msg->len > 0) {
		cnt = read(fd, buf, new_msg->len);
		memcpy(new_msg->buf, buf, new_msg->len);
		new_msg->buf[cnt] = 0;
	} else {
		new_msg->buf[0] = 0;
	}
	//MSG_PRINT("%s:%s: msg: %s, cnt: %lu\n", __FILE__, __func__,
	//	  new_msg->buf, cnt);
	/* Add msg to ring buffer */
	ringbuf_add(ringbuf, new_msg);
	MSG_PRINT("%s: syscall %d (len %u), rb head %lu, rb tail %lu. size %lu\n",
		  __func__, new_msg->syscall, new_msg->len,
		  ringbuf->head, ringbuf->tail, ringbuf->size);
}

/**
 * The main thread for receiving data.
 * */
void * msg_thread_main(void *args)
{
	/* Create socket and listen */
	if ((listenfd = create_server_socket()) < 0)
		abort();
	if (listen(listenfd, SOMAXCONN) < 0)
		fprintf(stderr, "listen socket error\n");

	/* Create epoll */
	if ((efd = epoll_create1(0)) == -1) {
		FATAL("epoll create error");
	}
	event.data.fd = listenfd;
	event.events = EPOLLIN;
	if (epoll_ctl(efd, EPOLL_CTL_ADD, listenfd, &event) < 0)
		fprintf(stderr, "epoll ctr error\n");

	/* Loop handling of the incoming connections and data messages. */
	while (1) {
		int nfds, i;
		/* nfds, events are output values */
		nfds = epoll_wait(efd, events, MAXEVENTS, -1);

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
				/* Process data processing on fd */
				process_data(events[i].data.fd);
			}
		}
	}

	close(listenfd);
}

/**
 * Initiate the msg receiver thread.
 * */
void msg_thread_init(void)
{
	pthread_t tid;

	/* Init the ring buffer */
	ringbuf = ringbuf_new();
	if (!ringbuf) FATAL("Ring buffer created failed\n");

	/* Create the messaging thread. */
	if (pthread_create(&tid, NULL, msg_thread_main, NULL)) {
		FATAL("Pthread create failed\n");
	}
	PRINT("pthread created\n");
}

