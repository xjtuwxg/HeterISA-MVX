#ifndef _MSG_SOCKET_H
#define _MSG_SOCKET_H

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
#include <semaphore.h>
#include <pthread.h>		// pthread_t
#include <sys/types.h>
#include <arpa/inet.h>		// inet_pton

#define MAXEVENTS	64
#define MSG_SIZE	4032

#ifndef NI_MAXHOST
#define NI_MAXHOST	1025
#endif
#ifndef NI_MAXSERV
#define NI_MAXSERV	32
#endif
#ifndef NI_NUMERICHOST
#define NI_NUMERICHOST	1
#endif

typedef struct sockaddr SA;
struct epoll_event event;
struct epoll_event events[MAXEVENTS];
int listenfd, efd;

typedef struct _message_t {
	char buf[MSG_SIZE];
	sem_t lock;
	size_t len;
	//int owner;
} msg_t;

msg_t msg;

typedef struct _message_epoll_t {
	int epfd;
	int event_num;
	int maxevents;
	int timeout;
	struct epoll_event events[MAXEVENTS];
} msg_epoll_t;

int create_client_socket(char *ip);
int create_server_socket(void);

void msg_thread_init(void);
void msg_wait_recv(msg_t *msg);

#endif
