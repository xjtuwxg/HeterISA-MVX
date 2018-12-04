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

/* Definations for ring buffer. */
#define MAX_RINGBUF_SIZE	256

typedef struct sockaddr SA;

/**
 * The message data structure, also the entry of ringbuf_t
 * */
typedef struct _message_t {
	long syscall;	// 8 bytes
	long len;	// 8 bytes
	char buf[MSG_SIZE];
} msg_t;


/**
 * head: index indicate the index of the next available msg slot for
 * the ring buffer message
 * */
struct ringbuf_t {
	msg_t *msg[MAX_RINGBUF_SIZE];
	size_t head, tail;
	size_t size;
	sem_t sem;
};
typedef struct ringbuf_t *ringbuf_t;

/* Epoll event in x86 format */
struct epoll_event_x86 {
	uint32_t events;
	epoll_data_t data;
} __attribute__ ((__packed__));

/*typedef struct _message_epoll_t {
	int epfd;
	int event_num;
	int maxevents;
	int timeout;
#if __x86_64__
	struct epoll_event events[MAXEVENTS];
#endif
#if __aarch64__
	// In order to pass epoll_event correctly on x86, we need to convert it
	// to 12 bytes.
	struct epoll_event_x86 events[MAXEVENTS];
#endif
} msg_epoll_t;*/

/**
 * Global variables for msg_socket.c (the message layer)
 * */
int listenfd, efd;
struct epoll_event event;
struct epoll_event events[MAXEVENTS];
ringbuf_t ringbuf;	// server/receiver side ring buffer
msg_t msg;		// client/sender side msg data struct


/* Socket related interfaces */
int create_client_socket(char *ip);
int create_server_socket(void);

void msg_thread_init(void);

/* Ring buffer related interfaces */
ringbuf_t ringbuf_new(void);
int ringbuf_add(ringbuf_t rb, msg_t *msg);
int ringbuf_del(ringbuf_t rb, msg_t *msg);

#endif
